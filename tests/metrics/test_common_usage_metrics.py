from twisted.test.proto_helpers import MemoryReactor

from synapse.metrics.common_usage_metrics import CommonUsageMetrics
from synapse.rest import admin, login, register, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests.test_utils import event_injection
from tests.unittest import FederatingHomeserverTestCase


class CommonUsageMetricsManagerTestCase(FederatingHomeserverTestCase):
    """
    Tests for the CommonUsageMetricsManager.
    """

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        register.register_servlets,
        login.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.manager = homeserver.get_common_usage_metrics_manager()

    def _perform_local_event_actions(self) -> None:
        """
        Perform some actions on the homeserver that would bump the CommonUsageMetrics

        This creates a user, a room, and sends some messages.
        Expected number of events:
         - 1 unencrypted messages
         - 1 encrypted messages
         - 9 total events (including room state, etc)
        """
        # Create user
        local_user_mxid = self.register_user(
            username="test_user_1",
            password="test",
        )
        local_user_token = self.login(username=local_user_mxid, password="test")

        # Create a room
        room_id = self.helper.create_room_as(
            is_public=False,
            tok=local_user_token,
        )

        # Mark the room as end-to-end encrypted
        self.helper.send_state(
            room_id=room_id,
            event_type="m.room.encryption",
            body={
                "algorithm": "m.megolm.v1.aes-sha2",
                "rotation_period_ms": 604800000,
                "rotation_period_msgs": 100,
            },
            state_key="",
            tok=local_user_token,
        )

        # Local user sends one unencrypted message
        self.helper.send(
            room_id=room_id,
            body="Unencrypted message",
            tok=local_user_token,
        )

        # Local user sends one encrypted message
        self.helper.send_event(
            room_id=room_id,
            type="m.room.encrypted",
            content={
                "algorithm": "m.olm.v1.curve25519-aes-sha2",
                "sender_key": "some_key",
                "ciphertext": {
                    "some_key": {
                        "type": 0,
                        "body": "encrypted_payload",
                    },
                },
            },
            tok=local_user_token,
        )

    def _perform_remote_event_actions(self) -> None:
        """
        Perform some actions on the homeserver that would bump the CommonUsageMetrics

        This creates users, a room, and sends some messages.
        Expected number of events:
         - 1 unencrypted messages
         - 1 encrypted messages
         - 3 total events (including room state, etc)
        """
        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        # Create a local user
        local_user_mxid = self.register_user(
            username="test_user_1",
            password="test",
        )
        local_user_token = self.login(username=local_user_mxid, password="test")

        # Create a room
        room_1_id = self.helper.create_room_as(
            is_public=True,
            tok=local_user_token,
        )

        # Allow the remote user to send state events
        self.helper.send_state(
            room_1_id,
            "m.room.power_levels",
            {"events_default": 0, "state_default": 0},
            tok=local_user_token,
        )

        # Make the room as end-to-end encrypted
        self.helper.send_state(
            room_id=room_1_id,
            event_type="m.room.encryption",
            body={
                "algorithm": "m.megolm.v1.aes-sha2",
                "rotation_period_ms": 604800000,
                "rotation_period_msgs": 100,
            },
            state_key="",
            tok=local_user_token,
        )

        # Add the remote user to the room
        self.get_success(
            event_injection.inject_member_event(self.hs, room_1_id, OTHER_USER, "join")
        )

        # Send an unencrypted message from the remote user
        self.get_success(
            event_injection.inject_event(
                self.hs,
                type="m.room.message",
                state_key="",
                sender=OTHER_USER,
                room_id=room_1_id,
                content={"msgtype": "m.text", "body": "Hello"},
            )
        )

        # Send an encrypted message from the remote user
        self.get_success(
            event_injection.inject_event(
                self.hs,
                type="m.room.encrypted",
                state_key="",
                sender=OTHER_USER,
                room_id=room_1_id,
                content={
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "sender_key": "some_key",
                    "ciphertext": {
                        "some_key": {
                            "type": 0,
                            "body": "encrypted_payload",
                        },
                    },
                },
            )
        )

    def test_local_event_metrics_update(self) -> None:
        """
        Check if the local event metrics are updated correctly after performing actions.
        """
        metrics = self.get_success(self.manager.get_metrics())
        self.assertIsInstance(metrics, CommonUsageMetrics)
        # Check initial values
        self.assertEqual(metrics.message_by_local, 0)
        self.assertEqual(metrics.event_by_local, 0)
        self.assertEqual(metrics.encrypted_event_by_local, 0)

        self._perform_local_event_actions()

        # Wait for the metrics to be updated
        self.reactor.advance(5 * 60)
        metrics = self.get_success(self.manager.get_metrics())
        self.assertEqual(metrics.message_by_local, 2)
        self.assertEqual(metrics.event_by_local, 9)
        self.assertEqual(metrics.encrypted_event_by_local, 1)

    def test_remote_event_metrics_update(self) -> None:
        """
        Check if the remote event metrics are updated correctly after performing actions.
        """
        metrics = self.get_success(self.manager.get_metrics())
        self.assertIsInstance(metrics, CommonUsageMetrics)
        # Check initial values
        self.assertEqual(metrics.message_by_remote, 0)
        self.assertEqual(metrics.event_by_remote, 0)
        self.assertEqual(metrics.encrypted_event_by_remote, 0)

        self._perform_remote_event_actions()

        # Wait for the metrics to be updated
        self.reactor.advance(5 * 60)
        metrics = self.get_success(self.manager.get_metrics())
        self.assertEqual(metrics.message_by_remote, 2)
        self.assertEqual(metrics.event_by_remote, 3)
        self.assertEqual(metrics.encrypted_event_by_remote, 1)
