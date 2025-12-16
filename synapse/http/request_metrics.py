#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2014-2016 OpenMarket Ltd
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#

import logging
import threading
import traceback
from typing import Mapping

from synapse.logging.context import current_context
from synapse.metrics import SERVER_NAME_LABEL, LaterGauge, meter

logger = logging.getLogger(__name__)


# total number of responses served, split by method/servlet/tag
response_count = meter.create_counter(
    "synapse_http_server_response_count",
)

requests_counter = meter.create_counter(
    "synapse_http_server_requests_received",
)

outgoing_responses_counter = meter.create_counter(
    "synapse_http_server_responses",
)

response_timer = meter.create_histogram(
    "synapse_http_server_response_time_seconds",
    unit="sec",
)

response_ru_utime = meter.create_counter(
    "synapse_http_server_response_ru_utime_seconds",
    description="sec",
)

response_ru_stime = meter.create_counter(
    "synapse_http_server_response_ru_stime_seconds",
    description="sec",
)

response_db_txn_count = meter.create_counter(
    "synapse_http_server_response_db_txn_count",
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
response_db_txn_duration = meter.create_counter(
    "synapse_http_server_response_db_txn_duration_seconds",
)

# seconds spent waiting for a db connection, when processing this request
response_db_sched_duration = meter.create_counter(
    "synapse_http_server_response_db_sched_duration_seconds",
)

# size in bytes of the response written
response_size = meter.create_counter(
    "synapse_http_server_response_size",
)

# In flight metrics are incremented while the requests are in flight, rather
# than when the response was written.

in_flight_requests_ru_utime = meter.create_counter(
    "synapse_http_server_in_flight_requests_ru_utime_seconds",
)

in_flight_requests_ru_stime = meter.create_counter(
    "synapse_http_server_in_flight_requests_ru_stime_seconds",
)

in_flight_requests_db_txn_count = meter.create_counter(
    "synapse_http_server_in_flight_requests_db_txn_count",
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
in_flight_requests_db_txn_duration = meter.create_counter(
    "synapse_http_server_in_flight_requests_db_txn_duration_seconds",
)

# seconds spent waiting for a db connection, when processing this request
in_flight_requests_db_sched_duration = meter.create_counter(
    "synapse_http_server_in_flight_requests_db_sched_duration_seconds",
)

_in_flight_requests: set["RequestMetrics"] = set()

# Protects the _in_flight_requests set from concurrent access
_in_flight_requests_lock = threading.Lock()


def _get_in_flight_counts() -> Mapping[tuple[str, ...], int]:
    """Returns a count of all in flight requests by (method, server_name)"""
    # Cast to a list to prevent it changing while the Prometheus
    # thread is collecting metrics
    with _in_flight_requests_lock:
        request_metrics = list(_in_flight_requests)

    for request_metric in request_metrics:
        request_metric.update_metrics()

    # Map from (method, name) -> int, the number of in flight requests of that
    # type. The key type is Tuple[str, str], but we leave the length unspecified
    # for compatability with LaterGauge's annotations.
    counts: dict[tuple[str, ...], int] = {}
    for request_metric in request_metrics:
        key = (
            request_metric.method,
            request_metric.name,
            request_metric.our_server_name,
        )
        counts[key] = counts.get(key, 0) + 1

    return counts


in_flight_requests = LaterGauge(
    name="synapse_http_server_in_flight_requests_count",
    desc="",
    labelnames=["method", "servlet", SERVER_NAME_LABEL],
)
in_flight_requests.register_hook(
    homeserver_instance_id=None, hook=_get_in_flight_counts
)


class RequestMetrics:
    def __init__(self, our_server_name: str) -> None:
        """
        Args:
            our_server_name: Our homeserver name (used to label metrics) (`hs.hostname`)
        """
        self.our_server_name = our_server_name

    def start(self, time_sec: float, name: str, method: str) -> None:
        self.start_ts = time_sec
        self.start_context = current_context()
        self.name = name
        self.method = method

        if self.start_context:
            # _request_stats records resource usage that we have already added
            # to the "in flight" metrics.
            self._request_stats = self.start_context.get_resource_usage()
        else:
            logger.error(
                "Tried to start a RequestMetric from the sentinel context.\n%s",
                "".join(traceback.format_stack()),
            )

        with _in_flight_requests_lock:
            _in_flight_requests.add(self)

    def stop(self, time_sec: float, response_code: int, sent_bytes: int) -> None:
        with _in_flight_requests_lock:
            _in_flight_requests.discard(self)

        context = current_context()

        tag = ""
        if context:
            tag = context.tag

            if context != self.start_context:
                logger.error(
                    "Context have unexpectedly changed %r, %r",
                    context,
                    self.start_context,
                )
                return
        else:
            logger.error(
                "Trying to stop RequestMetrics in the sentinel context.\n%s",
                "".join(traceback.format_stack()),
            )
            return

        response_code_str = str(response_code)

        outgoing_responses_counter.add(
            1,
            {
                "method": self.method,
                "code": response_code_str,
                SERVER_NAME_LABEL: self.our_server_name,
            },
        )

        response_base_labels = {
            "method": self.method,
            "servlet": self.name,
            "tag": tag,
            SERVER_NAME_LABEL: self.our_server_name,
        }

        response_count.add(1, response_base_labels)

        response_timer.record(
            time_sec - self.start_ts,
            {
                "code": response_code_str,
                **response_base_labels,
            },
        )

        resource_usage = context.get_resource_usage()

        response_ru_utime.add(resource_usage.ru_utime, response_base_labels)
        response_ru_stime.add(resource_usage.ru_stime, response_base_labels)
        response_db_txn_count.add(resource_usage.db_txn_count, response_base_labels)
        response_db_txn_duration.add(
            resource_usage.db_txn_duration_sec, response_base_labels
        )
        response_db_sched_duration.add(
            resource_usage.db_sched_duration_sec, response_base_labels
        )
        response_size.add(sent_bytes, response_base_labels)

        # We always call this at the end to ensure that we update the metrics
        # regardless of whether a call to /metrics while the request was in
        # flight.
        self.update_metrics()

    def update_metrics(self) -> None:
        """Updates the in flight metrics with values from this request."""
        if not self.start_context:
            logger.error(
                "Tried to update a RequestMetric from the sentinel context.\n%s",
                "".join(traceback.format_stack()),
            )
            return
        new_stats = self.start_context.get_resource_usage()

        diff = new_stats - self._request_stats
        self._request_stats = new_stats

        in_flight_labels = {
            "method": self.method,
            "servlet": self.name,
            SERVER_NAME_LABEL: self.our_server_name,
        }

        # max() is used since rapid use of ru_stime/ru_utime can end up with the
        # count going backwards due to NTP, time smearing, fine-grained
        # correction, or floating points. Who knows, really?
        in_flight_requests_ru_utime.add(max(diff.ru_utime, 0), in_flight_labels)
        in_flight_requests_ru_stime.add(max(diff.ru_stime, 0), in_flight_labels)

        in_flight_requests_db_txn_count.add(diff.db_txn_count, in_flight_labels)

        in_flight_requests_db_txn_duration.add(
            diff.db_txn_duration_sec, in_flight_labels
        )

        in_flight_requests_db_sched_duration.add(
            diff.db_sched_duration_sec, in_flight_labels
        )
