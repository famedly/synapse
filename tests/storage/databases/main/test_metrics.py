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

from prometheus_client import REGISTRY

from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.storage.databases.main.metrics import ServerMetricsStore
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class ServerMetricsStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # We can't test RoomStore on its own without the DirectoryStore, for
        # management of the 'room_aliases' table
        self.store = hs.get_datastores().main

    def test_room_metrics_registered(self) -> None:
        """
        Test following metrics are registered:
        - synapse_rooms_total
        - synapse_locally_joined_rooms_total
        """
        # Ensure the metrics are registered
        self.assertIn("synapse_rooms_total", REGISTRY._names_to_collectors)
        self.assertIn(
            "synapse_locally_joined_rooms_total", REGISTRY._names_to_collectors
        )

        # Check initial values
        self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 0)
        self.assertEqual(
            REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 0
        )

    def test_room_metrics_updated(self) -> None:
        """
        Test if registered metrics are updated correctly after the specified interval.
        """
        with patch.object(
            ServerMetricsStore,
            "set_number_of_rooms_gauge",
            wraps=self.store.set_number_of_rooms_gauge,
        ):
            with patch.object(
                self.store.db_pool, "runInteraction", new=AsyncMock(return_value=8)
            ):
                # Check initial values
                self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 0)

                # Check values after the update interval
                self.reactor.advance(60 * 60)
                self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 8)

        with patch.object(
            ServerMetricsStore,
            "set_locally_joined_rooms_gauge",
            wraps=self.store.set_locally_joined_rooms_gauge,
        ):
            with patch.object(
                self.store.db_pool, "runInteraction", new=AsyncMock(return_value=20)
            ):
                # Check initial values. It is same as the previous runInteraction mock value.
                self.assertEqual(
                    REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 8
                )

                # Check values after the update interval
                self.reactor.advance(60 * 60)
                self.assertEqual(
                    REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 20
                )
