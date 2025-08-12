from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.errors import Codes
from synapse.rest import admin
from synapse.rest.client import login, media
from synapse.server import HomeServer
from synapse.util import Clock

from tests.test_utils import SMALL_PNG
from tests.unittest import HomeserverTestCase, override_config


class BaseUploadServletTestCase(HomeserverTestCase):
    """
    Base class for upload servlet tests.
    """

    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repo = hs.get_media_repository_resource()
        self.register_user("testuser", "testpass")
        self.tok = self.login("testuser", "testpass")

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    @override_config(
        {"experimental_features": {"msc3911_unrestricted_media_upload_disabled": True}}
    )
    def test_disable_unrestricted_media_upload_post(self) -> None:
        """
        Tests that the upload servlet raises an error when unrestricted media upload is disabled.
        """

        channel = self.make_request(
            "POST",
            "/_matrix/media/v3/upload?filename=test_png_upload",
            SMALL_PNG,
            access_token=self.tok,
            shorthand=False,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(67))],
        )
        self.assertEqual(channel.code, 403)
        self.assertEqual(channel.json_body["errcode"], Codes.FORBIDDEN)

    @override_config(
        {"experimental_features": {"msc3911_unrestricted_media_upload_disabled": True}}
    )
    def test_disable_unrestricted_media_upload_put(self) -> None:
        """
        Tests that the upload servlet raises an error when unrestricted media upload is disabled.
        """
        server_name = self.hs.hostname
        response = self.make_request(
            "PUT",
            f"/_matrix/media/v3/upload/{server_name}/test_png_upload",
            content=b"dummy file content",
            content_type=b"image/png",
            access_token=self.tok,
        )
        self.assertEqual(response.code, 403)
        self.assertEqual(response.json_body["errcode"], Codes.FORBIDDEN)
