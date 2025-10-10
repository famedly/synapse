#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2022 The Matrix.org Foundation C.I.C
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
from dataclasses import dataclass
from typing import TYPE_CHECKING

import attr

from synapse.metrics import SERVER_NAME_LABEL
from synapse.metrics.background_process_metrics import run_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

from prometheus_client import Gauge

# Gauge to expose daily active users metrics
current_dau_gauge = Gauge(
    "synapse_admin_daily_active_users",
    "Current daily active users count",
    labelnames=[SERVER_NAME_LABEL],
)

# Gauge for users
users_in_status_gauge = Gauge(
    "synapse_user_count",
    "Number of users in active, deactivated, suspended, and locked status",
    ["status", SERVER_NAME_LABEL],
)

users_in_time_ranges_gauge = Gauge(
    "synapse_active_users",
    "Number of active users in time ranges in 24h, 7d, and 30d",
    ["time_range", SERVER_NAME_LABEL],
)

# We may want to add additional ranges in the future.
retained_users_gauge = Gauge(
    "synapse_retained_users",
    "Number of retained users in 30d",
    ["time_range", SERVER_NAME_LABEL],
)


@dataclass
class UserMetrics:
    active: int = 0
    deactivated: int = 0
    suspended: int = 0
    locked: int = 0
    retained_30d: int = 0


@attr.s(auto_attribs=True)
class CommonUsageMetrics:
    """Usage metrics shared between the phone home stats and the prometheus exporter."""

    # active users in time ranges
    daily_active_users: int
    weekly_active_users: int
    monthly_active_users: int

    # user counts in different states
    active_users: int
    deactivated_users: int
    suspended_users: int
    locked_users: int

    # retained users in time ranges
    monthly_retained_users: int


class CommonUsageMetricsManager:
    """Collects common usage metrics."""

    def __init__(self, hs: "HomeServer") -> None:
        self.server_name = hs.hostname
        self._store = hs.get_datastores().main
        self._clock = hs.get_clock()

    async def get_metrics(self) -> CommonUsageMetrics:
        """Get the CommonUsageMetrics object. If no collection has happened yet, do it
        before returning the metrics.

        Returns:
            The CommonUsageMetrics object to read common metrics from.
        """
        return await self._collect()

    async def setup(self) -> None:
        """Keep the gauges for common usage metrics up to date."""
        run_as_background_process(
            desc="common_usage_metrics_update_gauges",
            server_name=self.server_name,
            func=self._update_gauges,
        )
        self._clock.looping_call(
            run_as_background_process,
            5 * 60 * 1000,
            desc="common_usage_metrics_update_gauges",
            server_name=self.server_name,
            func=self._update_gauges,
        )

    async def _collect(self) -> CommonUsageMetrics:
        """Collect the common metrics and either create the CommonUsageMetrics object to
        use if it doesn't exist yet, or update it.
        """
        dau_count = await self._store.count_daily_users()
        wau_count = await self._store.count_weekly_users()
        mau_count = await self._store.count_monthly_users()

        user_metric: UserMetrics = await self._store.get_user_count_per_status()

        return CommonUsageMetrics(
            daily_active_users=dau_count,
            weekly_active_users=wau_count,
            monthly_active_users=mau_count,
            active_users=user_metric.active,
            deactivated_users=user_metric.deactivated,
            suspended_users=user_metric.suspended,
            locked_users=user_metric.locked,
            monthly_retained_users=user_metric.retained_30d,
        )

    async def _update_gauges(self) -> None:
        """Update the Prometheus gauges."""
        metrics = await self._collect()

        current_dau_gauge.labels(
            **{SERVER_NAME_LABEL: self.server_name},
        ).set(float(metrics.daily_active_users))

        time_range_to_metric = {
            "24h": metrics.daily_active_users,
            "7d": metrics.weekly_active_users,
            "30d": metrics.monthly_active_users,
        }
        for time_range, _metric in time_range_to_metric.items():
            users_in_time_ranges_gauge.labels(
                time_range=time_range, **{SERVER_NAME_LABEL: self.server_name}
            ).set(float(_metric))

        status_to_metric = {
            "active": metrics.active_users,
            "deactivated": metrics.deactivated_users,
            "suspended": metrics.suspended_users,
            "locked": metrics.locked_users,
        }
        for status, _metric in status_to_metric.items():
            users_in_status_gauge.labels(
                status=status, **{SERVER_NAME_LABEL: self.server_name}
            ).set(float(_metric))

        retained_users_gauge.labels(
            time_range="30d", **{SERVER_NAME_LABEL: self.server_name}
        ).set(float(metrics.monthly_retained_users))
