from typing import TYPE_CHECKING

from twisted.internet.testing import MemoryReactor

from synapse.api.errors import Codes
from synapse.rest.admin import register_servlets
from synapse.rest.client import login
from synapse.util.clock import Clock

from tests import unittest

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ModulesRestTestCase(unittest.HomeserverTestCase):
    servlets = [
        register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: "HomeServer") -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

    def test_no_auth(self) -> None:
        """
        Try to get modules information without authentication.
        """
        channel = self.make_request("GET", "/_synapse/admin/v1/modules", b"{}")
        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_not_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/modules",
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_get_modules(self) -> None:
        """
        Test that endpoint returns loaded modules information.
        """
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/modules",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Check that the response has the expected structure
        self.assertIn("modules", channel.json_body)
        self.assertIsInstance(channel.json_body["modules"], list)

        # Each module should have name and version
        for module in channel.json_body["modules"]:
            self.assertIn("module_name", module)
            self.assertIn("package_name", module)
            self.assertIn("version", module)
            self.assertIsInstance(module["module_name"], str)
            self.assertIsInstance(module["package_name"], str)
            self.assertIsInstance(module["version"], str)
