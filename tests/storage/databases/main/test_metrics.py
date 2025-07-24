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
import logging
from unittest.mock import patch

from synapse.metrics import REGISTRY
from synapse.storage.databases.main.metrics import (
    GAUGE_METRICS_CONFIG,
    REGISTERED_METRICS,
)

from tests.unittest import HomeserverTestCase

logger = logging.getLogger(__name__)


class MetricsTestCase(HomeserverTestCase):
    def tearDown(self) -> None:
        # Ensures that metrics do not persist across tests.
        for config in GAUGE_METRICS_CONFIG:
            collector = REGISTERED_METRICS.get(config["name"])
            if collector:
                try:
                    REGISTRY.unregister(collector)
                    REGISTERED_METRICS.pop(config["name"], None)
                except Exception:
                    logger.error(
                        "Failed to unregister metric %s in tearDown.", config["name"]
                    )
        super().tearDown()

    def test_gauge_metrics_config_registered(self) -> None:
        """
        Test metrics that are defined in GAUGE_METRICS_CONFIG are correctly registered.
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

    def test_registered_metrics_update_interval(self) -> None:
        """
        Test if the registered metrics from GAUGE_METRICS_CONFIG are updated correctly
        after the specified interval.
        """

        def fetch_gauge_value_side_effect(
            sql: str, params: tuple, metric_name: str
        ) -> int:
            if metric_name == "synapse_rooms_total":
                return 10
            elif metric_name == "synapse_locally_joined_rooms_total":
                return 8
            return 0

        with patch.object(
            self.hs.get_datastores().main,
            "_fetch_gauge_value",
            side_effect=fetch_gauge_value_side_effect,
        ):
            # The metrics registered before patching must be unregistered.
            for config in GAUGE_METRICS_CONFIG:
                collector = REGISTERED_METRICS.get(config["name"])
                if collector:
                    REGISTRY.unregister(collector)
                    REGISTERED_METRICS.pop(config["name"], None)

            # Re-register metrics after patching
            self.hs.get_datastores().main.setup_metrics()

            # Check initial values
            self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 0)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 0
            )

            # Check values after the update interval
            self.reactor.advance(15)
            self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 10)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 8
            )
