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
from typing import TYPE_CHECKING

import attr

from synapse.metrics.background_process_metrics import run_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

from prometheus_client import Gauge

# Gauge to expose daily active users metrics
current_dau_gauge = Gauge(
    "synapse_admin_daily_active_users",
    "Current daily active users count",
)

# Gauge for users
users_in_status_gauge = Gauge(
    "synapse_user_count",
    "Number of users in active, deactivated, suspended, and locked status",
    ["status"],
)

users_in_time_ranges_gauge = Gauge(
    "synapse_active_users",
    "Number of active users in time ranges in 24h, 7d, and 30d",
    ["time_range"],
)

# We may want to add additional ranges in the future.
retained_users_gauge = Gauge(
    "synapse_retained_users", "Number of retained users in 30d", ["time_range"]
)


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
            desc="common_usage_metrics_update_gauges", func=self._update_gauges
        )
        self._clock.looping_call(
            run_as_background_process,
            5 * 60 * 1000,
            desc="common_usage_metrics_update_gauges",
            func=self._update_gauges,
        )

    async def _collect(self) -> CommonUsageMetrics:
        """Collect the common metrics and either create the CommonUsageMetrics object to
        use if it doesn't exist yet, or update it.
        """
        dau_count = await self._store.count_daily_users()
        wau_count = await self._store.count_weekly_users()
        mau_count = await self._store.count_monthly_users()

        active = await self._store.count_users_per_status(
            {"deactivated": 0, "locked": False, "suspended": False}
        )
        deactivated = await self._store.count_users_per_status({"deactivated": 1})
        suspended = await self._store.count_users_per_status({"suspended": True})
        locked = await self._store.count_users_per_status({"locked": True})
        count_r30v2_users = await self._store.count_r30v2_users()
        monthly_retained = count_r30v2_users.get("all", 0)

        return CommonUsageMetrics(
            daily_active_users=dau_count,
            weekly_active_users=wau_count,
            monthly_active_users=mau_count,
            active_users=active,
            deactivated_users=deactivated,
            suspended_users=suspended,
            locked_users=locked,
            monthly_retained_users=monthly_retained,
        )

    async def _update_gauges(self) -> None:
        """Update the Prometheus gauges."""
        metrics = await self._collect()

        current_dau_gauge.set(float(metrics.daily_active_users))
        users_in_time_ranges_gauge.labels(time_range="24h").set(
            float(metrics.daily_active_users)
        )
        users_in_time_ranges_gauge.labels(time_range="7d").set(
            float(metrics.weekly_active_users)
        )
        users_in_time_ranges_gauge.labels(time_range="30d").set(
            float(metrics.monthly_active_users)
        )
        users_in_status_gauge.labels(status="active").set(float(metrics.active_users))
        users_in_status_gauge.labels(status="deactivated").set(
            float(metrics.deactivated_users)
        )
        users_in_status_gauge.labels(status="suspended").set(
            float(metrics.suspended_users)
        )
        users_in_status_gauge.labels(status="locked").set(float(metrics.locked_users))

        retained_users_gauge.labels(time_range="30d").set(
            float(metrics.monthly_retained_users)
        )
