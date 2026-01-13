from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin, login, register, room
from synapse.server import HomeServer
from synapse.types import create_requester
from synapse.util.clock import Clock
from synapse.util.duration import Duration

from tests.unittest import FederatingHomeserverTestCase


class CommonUsageMetricsManagerTestCase(FederatingHomeserverTestCase):
    """
    Tests for the CommonUsageMetricsManager.
    """

    servlets = [
        admin.register_servlets,
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        register.register_servlets,
        login.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.manager = homeserver.get_common_usage_metrics_manager()
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_token = self.login(self.admin_user, "pass")

    def _create_active_user(self, prefix: str, i: int) -> str:
        """
        Create given number of active users.
        """
        username = "%s_active_user_%d" % (prefix, i)
        self.register_user(
            username=username,
            password="test",
        )
        user_tok = self.login(username=username, password="test")
        room_id = self.helper.create_room_as(room_creator=username, tok=user_tok)
        self.helper.send(room_id, "message", tok=user_tok)
        return user_tok

    def test_users_in_status_gauge_update(self) -> None:
        """
        Test that the users_in_status_gauge updates correctly.
        """
        metrics = self.get_success(self.manager.get_metrics())

        # Check initial values
        self.assertEqual(metrics.active_users, 1)  # 1 admin
        self.assertEqual(metrics.deactivated_users, 0)
        self.assertEqual(metrics.suspended_users, 0)
        self.assertEqual(metrics.locked_users, 0)

        # Create an active user
        self._create_active_user("t", 1)

        # Create a deactivated user
        user_mxid = self.register_user(
            username="deactivated_user",
            password="test",
        )
        self.login(username=user_mxid, password="test")
        deactivate_handler = self.hs.get_deactivate_account_handler()
        self.get_success(
            deactivate_handler.deactivate_account(
                user_mxid, erase_data=False, requester=create_requester(self.admin_user)
            )
        )

        # Create a suspended user
        user_mxid = self.register_user(
            username="suspended_user",
            password="test",
        )
        self.login("suspended_user", "test")
        channel = self.make_request(
            "PUT",
            f"/_synapse/admin/v1/suspend/{user_mxid}",
            {"suspend": True},
            access_token=self.admin_token,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body, {f"user_{user_mxid}_suspended": True})

        # Create a locked user
        user_mxid = self.register_user(
            username="locked_user",
            password="test",
        )
        self.login(username=user_mxid, password="test")
        self.get_success(
            self.hs.get_datastores().main.set_user_locked_status(user_mxid, True)
        )

        # Wait for the metrics to be updated
        self.reactor.advance(5 * 60)
        metrics = self.get_success(self.manager.get_metrics())

        self.assertEqual(metrics.active_users, 2)  # 1 admin and 1 active user
        self.assertEqual(metrics.deactivated_users, 1)
        self.assertEqual(metrics.suspended_users, 1)
        self.assertEqual(metrics.locked_users, 1)

    def test_users_in_time_ranges_gauge_update(self) -> None:
        """
        Test that the users_in_time_ranges_gauge updates correctly.
        """
        metrics = self.get_success(self.manager.get_metrics())

        # Check initial values
        self.assertEqual(metrics.daily_active_users, 0)
        self.assertEqual(metrics.weekly_active_users, 0)
        self.assertEqual(metrics.monthly_active_users, 0)

        # Simulate active users per time range
        # create four monthly active users.
        for i in range(4):
            self._create_active_user("monthly", i)
            self.reactor.advance(60 * 60 * 24 * 5)  # Simulate time passing by 5 days
        # create five weekly active users.
        for i in range(5):
            self._create_active_user("weekly", i)
            self.reactor.advance(60 * 60 * 24)  # Simulate time passing by 1 day

        # create five daily active users.
        for i in range(5):
            self._create_active_user("daily", i)
            self.reactor.advance(60 * 60)  # Simulate time passing by 1 hour

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v2/users",
            access_token=self.admin_token,
        )
        self.assertEqual(200, channel.code)
        self.assertEqual(
            len(channel.json_body["users"]), 15
        )  # 5 daily, 5 weekly, 4 monthly, 1 admin

        # Wait for the metrics to be updated
        self.reactor.advance(5 * 60)
        metrics = self.get_success(self.manager.get_metrics())

        self.assertEqual(metrics.daily_active_users, 6)  # 5 daily + 1 admin
        self.assertEqual(
            metrics.weekly_active_users, 11
        )  # 5 weekly + 5 daily + 1 admin
        self.assertEqual(
            metrics.monthly_active_users, 15
        )  # 4 monthly + 5 weekly + 5 daily + 1 admin

    def test_retained_users_gauge_update(self) -> None:
        """
        Test that the retained users gauge updates correctly.
        """
        # start the user_daily_visits table update loop
        self.clock.looping_call(
            self.hs.get_datastores().main.generate_user_daily_visits,
            Duration(minutes=5),
        )
        metrics = self.get_success(self.manager.get_metrics())

        # Check initial values
        self.assertEqual(metrics.monthly_retained_users, 0)

        # Simulate retained users
        for i in range(5):
            self._create_active_user("retained", i)

        # Give time for user_daily_visits table to be updated.
        self.reactor.advance(60 * 5)

        # Simulate time passing by 31 days
        self.reactor.advance(60 * 60 * 24 * 31)

        for i in range(5):
            user_tok = self.login(
                username="retained_active_user_%s" % i, password="test"
            )
            room_id = self.helper.create_room_as(
                room_creator="retained_active_user_%s" % i, tok=user_tok
            )
            self.helper.send(room_id, "new message", tok=user_tok)

        # Let another user_daily_visits update occur
        self.reactor.advance(60 * 5)

        # Wait for the metrics to be updated
        self.reactor.advance(5 * 60)
        metrics = self.get_success(self.manager.get_metrics())

        self.assertEqual(metrics.monthly_retained_users, 5)
