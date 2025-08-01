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
from typing import Optional
from unittest.mock import AsyncMock, patch

from prometheus_client import REGISTRY

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest.admin import register_servlets_for_client_rest_resource
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class ServerMetricsStoreTestCase(HomeserverTestCase):
    servlets = [
        register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def assert_count_events_sql(
        self,
        event_types: Optional[list[str]],
        local: bool,
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
            self.get_success(
                self.store._count_events(event_types=event_types, local=local)
            )
            # Get the function passed to runInteraction
            interaction_fn = mock_run.call_args[0][1]
            # Create a mock txn object
            txn = Txn()
            # Run the interaction function
            interaction_fn(txn)
            self.assertEqual(txn.sql, expected_sql)
            self.assertEqual(txn.params, expected_params)

   
    def test_count_events_sql(self) -> None:
        hostname = self.store.hs.hostname
        self.assert_count_events_sql(
            event_types=["m.room.message", "m.room.encrypted"],
            local=True,
            expected_sql="SELECT COUNT(*) FROM events WHERE type IN (?, ?) AND sender LIKE ?",
            expected_params=("m.room.message", "m.room.encrypted", "%:" + hostname),
        )
        self.assert_count_events_sql(
            event_types=None,
            local=False,
            expected_sql="SELECT COUNT(*) FROM events WHERE sender NOT LIKE ?",
            expected_params=("%:" + hostname,),
        )
        self.assert_count_events_sql(
            event_types=["m.room.encrypted"],
            local=False,
            expected_sql="SELECT COUNT(*) FROM events WHERE type IN (?) AND sender NOT LIKE ?",
            expected_params=("m.room.encrypted", "%:" + hostname),
        )

    def test_set_event_metrics(self) -> None:
        with patch.object(
            self.store, "_count_events", new=AsyncMock(side_effect=[5, 10])
        ):
            self.get_success(self.store.set_messages_by_source_gauge())
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_messages_by_source", {"source": "local"}
                ),
                5,
            )
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_messages_by_source", {"source": "remote"}
                ),
                10,
            )

        with patch.object(
            self.store, "_count_events", new=AsyncMock(side_effect=[7, 12])
        ):
            self.get_success(self.store.set_events_by_source_gauge())
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_events_by_source", {"source": "local"}
                ),
                7,
            )
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_events_by_source", {"source": "remote"}
                ),
                12,
            )

        with patch.object(
            self.store, "_count_events", new=AsyncMock(side_effect=[3, 4])
        ):
            self.get_success(self.store.set_encrypted_events_by_source_gauge())
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_encrypted_events_by_source", {"source": "local"}
                ),
                3,
            )
            self.assertEqual(
                REGISTRY.get_sample_value(
                    "synapse_encrypted_events_by_source", {"source": "remote"}
                ),
                4,
            )
