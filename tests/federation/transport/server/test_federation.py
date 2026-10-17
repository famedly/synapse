from synapse.types import JsonDict

from tests import unittest


class TestAuthenticatedFederationVersionEndpoint(unittest.FederatingHomeserverTestCase):
    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.update({"require_auth_for_server_version": True})
        return config

    def test_endpoint(self) -> None:
        # Un-authed requests to endpoints that require them return a 401
        channel = self.make_request(
            "GET", "/_matrix/federation/v1/version", shorthand=False
        )
        assert channel.code == 401, channel

        # Authing the request works as expected
        channel = self.make_signed_federation_request(
            "GET", "/_matrix/federation/v1/version"
        )
        assert channel.code == 200, channel
