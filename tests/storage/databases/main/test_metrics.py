from synapse.metrics import REGISTRY
from tests.unittest import HomeserverTestCase
from unittest.mock import AsyncMock, patch
from synapse.storage.databases.main.room import RoomWorkerStore


class MetricsTestCase(HomeserverTestCase):
    def test_room_count_metrics_registered(self) -> None:
        """
        Test that room count metrics are correctly registered and updated.
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

    def test_room_count_metrics_updated(self) -> None:
        """
        Test that room count metrics are updated correctly.
        """
        with patch.object(
            RoomWorkerStore,
            "get_room_count",
            new=AsyncMock(return_value=40),
        ), patch.object(
            RoomWorkerStore,
            "get_locally_joined_room_count",
            new=AsyncMock(return_value=25),
        ):
            self.setup_test_homeserver()
            # Check initial values
            self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 0)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 0
            )
            # Run the background update
            self.reactor.advance(35)
            # Check updated values
            self.assertEqual(REGISTRY.get_sample_value("synapse_rooms_total"), 40)
            self.assertEqual(
                REGISTRY.get_sample_value("synapse_locally_joined_rooms_total"), 25
            )
