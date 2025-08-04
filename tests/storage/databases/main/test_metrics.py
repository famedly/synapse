#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from unittest.mock import AsyncMock, patch

from prometheus_client import REGISTRY, Gauge

from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class ServerMetricsStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def assert_count_users_per_status(
        self,
        status: dict,
        expected_sql: str,
        expected_params: tuple,
    ) -> None:
        class Txn:
            def __init__(self) -> None:
                self.sql: str = ""
                self.params: tuple = ()

            def execute(self, sql: str, params: tuple) -> None:
                self.sql = sql
                self.params = params

            def fetchone(self) -> tuple[int]:
                return (100,)

        with patch.object(self.store.db_pool, "runInteraction") as mock_run:
            self.get_success(self.store.count_users_per_status(status))
            # Get the function passed to runInteraction
            interaction_fn = mock_run.call_args[0][1]
            # Create a mock txn object
            txn = Txn()
            # Run the interaction function
            interaction_fn(txn)
            self.assertEqual(txn.sql, expected_sql)
            self.assertEqual(txn.params, expected_params)

    def test_room_metrics_registered(self) -> None:
        """
        Test following metrics are registered:
        - synapse_known_rooms_total
        - synapse_locally_joined_rooms_total
        """
        # Ensure the metrics are registered
        self.assertIn("synapse_known_rooms_total", REGISTRY._names_to_collectors)
        self.assertIn(
            "synapse_locally_joined_rooms_total", REGISTRY._names_to_collectors
        )

    def test_set_room_metrics(self) -> None:
        """
        Test set metric functions for room metrics.
        """
        with patch.object(self.store, "get_room_count", new=AsyncMock(return_value=5)):
            self.get_success(self.store.set_known_rooms_gauge())
            self.assertEqual(REGISTRY.get_sample_value("synapse_known_rooms_total"), 5)
        with patch.object(
            self.store, "get_locally_joined_room_count", new=AsyncMock(return_value=10)
        ):
            self.get_success(self.store.set_locally_joined_rooms_gauge())
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 10
            )

    def test_room_metrics_updated_after_interval(self) -> None:
        """
        Test if registered metrics are updated correctly after the specified interval.
        """
        # Set initial values
        gauge = REGISTRY._names_to_collectors.get("synapse_known_rooms_total")
        if isinstance(gauge, Gauge):
            gauge.set(0)
        self.assertEqual(REGISTRY.get_sample_value("synapse_known_rooms_total"), 0)

        with patch.object(self.store, "get_room_count", new=AsyncMock(return_value=8)):
            # Check values after the update interval
            self.reactor.advance(60 * 60)
            self.assertEqual(REGISTRY.get_sample_value("synapse_known_rooms_total"), 8)

        gauge = REGISTRY._names_to_collectors.get("synapse_locally_joined_rooms_total")
        if isinstance(gauge, Gauge):
            gauge.set(0)
        self.assertEqual(
            REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 0
        )

        with patch.object(
            self.store, "get_locally_joined_room_count", new=AsyncMock(return_value=20)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 20
            )

    def test_user_metrics_registered(self) -> None:
        """
        Test following metrics are registered:
        - synapse_users
        - synapse_active_users
        - synapse_retained_users
        """
        self.assertIn("synapse_user_count", REGISTRY._names_to_collectors)
        self.assertIn("synapse_active_users", REGISTRY._names_to_collectors)
        self.assertIn("synapse_retained_users", REGISTRY._names_to_collectors)

    def test_count_users_per_status(self) -> None:
        """
        Test the SQL query for counting users with different status.
        """
        # Test with 'active' status
        self.assert_count_users_per_status(
            {"deactivated": 0, "locked": False, "suspended": False},
            "SELECT COUNT(*) FROM users WHERE deactivated = ? AND locked = ? AND suspended = ?",
            (0, False, False),
        )
        # Test with 'inactive' status
        self.assert_count_users_per_status(
            {"deactivated": 1},
            "SELECT COUNT(*) FROM users WHERE deactivated = ?",
            (1,),
        )
        # Test with 'suspended' status
        self.assert_count_users_per_status(
            {"suspended": True},
            "SELECT COUNT(*) FROM users WHERE suspended = ?",
            (True,),
        )
        # Test with 'locked' status
        self.assert_count_users_per_status(
            {"locked": True},
            "SELECT COUNT(*) FROM users WHERE locked = ?",
            (True,),
        )

    def test_set_users_in_status_gauge(self) -> None:
        """
        Test set metric functions for user metrics.
        """
        with patch.object(
            self.store,
            "count_users_per_status",
            new=AsyncMock(side_effect=[3, 4, 5, 6]),
        ):
            self.get_success(self.store.set_users_in_status_gauge())
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_user_count", {"status": "active"}), 3
            )
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_user_count", {"status": "deactivated"}
                ),
                4,
            )
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_user_count", {"status": "suspended"}
                ),
                5,
            )
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_user_count", {"status": "locked"}), 6
            )

    def test_synapse_user_count_updated_after_interval(self) -> None:
        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_user_count", {"status": "active"}), 8
        )
        with patch.object(
            self.store, "count_users_per_status", new=AsyncMock(return_value=8)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_user_count", {"status": "active"}), 8
            )

        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_user_count", {"status": "deactivated"}),
            9,
        )
        with patch.object(
            self.store, "count_users_per_status", new=AsyncMock(return_value=9)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_user_count", {"status": "deactivated"}
                ),
                9,
            )

        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_user_count", {"status": "suspended"}), 10
        )
        with patch.object(
            self.store, "count_users_per_status", new=AsyncMock(return_value=10)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_user_count", {"status": "suspended"}
                ),
                10,
            )

        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_user_count", {"status": "locked"}), 11
        )
        with patch.object(
            self.store, "count_users_per_status", new=AsyncMock(return_value=11)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_user_count", {"status": "locked"}),
                11,
            )

    def test_synapse_active_users_updated_after_interval(self) -> None:
        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_active_users", {"time_range": "24h"}), 5
        )
        with patch.object(
            self.store, "count_daily_users", new=AsyncMock(return_value=5)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_active_users", {"time_range": "24h"}
                ),
                5,
            )

        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_active_users", {"time_range": "7d"}), 6
        )
        with patch.object(
            self.store, "count_weekly_users", new=AsyncMock(return_value=6)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_active_users", {"time_range": "7d"}),
                6,
            )

        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_active_users", {"time_range": "30d"}), 7
        )
        with patch.object(
            self.store, "count_monthly_users", new=AsyncMock(return_value=7)
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_active_users", {"time_range": "30d"}
                ),
                7,
            )

    def test_synapse_retained_users_updated_after_interval(self) -> None:
        self.assertNotEqual(
            REGISTRY.get_sample_value("synapse_retained_users", {"time_range": "30d"}),
            8,
        )
        with patch.object(
            self.store,
            "count_r30v2_users",
            new=AsyncMock(return_value={"ios": 0, "android": 0, "web": 0, "all": 8}),
        ):
            self.reactor.advance(60 * 60)
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_retained_users", {"time_range": "30d"}
                ),
                8,
            )
