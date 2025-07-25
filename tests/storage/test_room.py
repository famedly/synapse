#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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

from synapse.api.room_versions import RoomVersions
from synapse.server import HomeServer
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.types import RoomAlias, RoomID, UserID
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class RoomStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # We can't test RoomStore on its own without the DirectoryStore, for
        # management of the 'room_aliases' table
        self.store = hs.get_datastores().main

        self.room = RoomID.from_string("!abcde:test")
        self.alias = RoomAlias.from_string("#a-room-name:test")
        self.u_creator = UserID.from_string("@creator:test")

        self.get_success(
            self.store.store_room(
                self.room.to_string(),
                room_creator_user_id=self.u_creator.to_string(),
                is_public=True,
                room_version=RoomVersions.V1,
            )
        )

    def test_get_room(self) -> None:
        room = self.get_success(self.store.get_room(self.room.to_string()))
        assert room is not None
        self.assertTrue(room[0])

    def test_get_room_unknown_room(self) -> None:
        self.assertIsNone(self.get_success(self.store.get_room("!uknown:test")))

    def test_get_room_with_stats(self) -> None:
        res = self.get_success(self.store.get_room_with_stats(self.room.to_string()))
        assert res is not None
        self.assertEqual(res.room_id, self.room.to_string())
        self.assertEqual(res.creator, self.u_creator.to_string())
        self.assertTrue(res.public)

    def test_get_room_with_stats_unknown_room(self) -> None:
        self.assertIsNone(
            self.get_success(self.store.get_room_with_stats("!uknown:test"))
        )

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
            RoomWorkerStore, "get_room_count", wraps=self.store.get_room_count
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
            RoomWorkerStore,
            "get_locally_joined_room_count",
            wraps=self.store.get_locally_joined_room_count,
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
