import io
import os

from matrix_common.types.mxc_uri import MXCUri
from PIL import Image as Image

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media._base import FileInfo
from synapse.media.filepath import MediaFilePaths
from synapse.media.media_repository import MediaRepository
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG


class RestrictedMediaDeduplicationTestCase(unittest.HomeserverTestCase):
    extra_config = {
        "experimental_features": {"msc3911_enabled": True},
    }

    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config.update(self.extra_config)
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.media_repository = hs.get_media_repository()
        assert isinstance(self.media_repository, MediaRepository)
        self.profile_handler = self.hs.get_profile_handler()
        self.user = self.register_user("user", "testpass")
        self.user_tok = self.login("user", "testpass")
        self.other_user = self.register_user("other", "testpass")
        self.other_user_tok = self.login("other", "testpass")
        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)

        self.remote = "example.com"
        self.media_id = "12345"

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def create_restricted_media(self, user: str) -> MXCUri:
        mxc_uri = self.get_success(
            self.media_repository.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(user),
                restricted=True,
            )
        )
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(mxc_uri.media_id)
        )
        assert uploaded_media is not None
        assert uploaded_media.attachments is None

        local_path = self.filepaths.local_media_filepath(mxc_uri.media_id)
        assert os.path.exists(local_path)

        return mxc_uri

    def generate_path_from_media_id(self, media_id: str) -> str:
        return f"{media_id[:2]}/{media_id[2:4]}/{media_id[4:]}"

    def test_upload_media_with_original_media_id_field(self) -> None:
        """
        Test that uploading same media again will create media with original_media_id field.
        """
        # Create an original media and make sure it's written to the file
        original_mxc = self.create_restricted_media(self.user)

        # Upload another media with the same file
        channel = self.make_request(
            "POST",
            "/_matrix/client/unstable/org.matrix.msc3911/media/upload?filename=new_name",
            content=SMALL_PNG,
            content_type=b"image/png",
            access_token=self.user_tok,
            custom_headers=[("Content-Length", str(67))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None
        media_id = mxc_uri_str.rsplit("/", 1)[-1]

        # Make sure the new media is saved with the `original_media_id`
        media_info = self.get_success(
            self.media_repository.store.get_local_media(media_id)
        )
        assert media_info is not None
        assert media_info.original_media_id is not None
        assert "synapse/media/local_content" in media_info.original_media_id
        assert (
            self.generate_path_from_media_id(original_mxc.media_id)
            in media_info.original_media_id
        )

    def test_async_upload_media_with_original_media_id_field(self) -> None:
        """
        Test that async upload endpoint can handle duplicated media with
        original_media_id field.
        """
        # Create original file
        original_mxc = self.create_restricted_media(self.user)
        # Create media id with create endpoint
        channel = self.make_request(
            "POST",
            "/_matrix/client/unstable/org.matrix.msc3911/media/create",
            content=SMALL_PNG,
            content_type=b"image/png",
            access_token=self.user_tok,
            custom_headers=[("Content-Length", str(67))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None
        media_id = mxc_uri_str.rsplit("/", 1)[-1]

        # Now upload media via async upload
        channel = self.make_request(
            "PUT",
            f"/_matrix/media/v3/upload/{self.hs.hostname}/{media_id}",
            content=SMALL_PNG,
            content_type=b"image/png",
            access_token=self.user_tok,
            custom_headers=[("Content-Length", str(67))],
        )
        assert channel.code == 200, channel.json_body

        # Check if media is marked with the original_media_id
        media_info = self.get_success(
            self.media_repository.store.get_local_media(media_id)
        )
        assert media_info is not None
        assert media_info.original_media_id is not None
        assert "synapse/media/local_content" in media_info.original_media_id
        assert (
            self.generate_path_from_media_id(original_mxc.media_id)
            in media_info.original_media_id
        )

    def test_copy_local_media_with_original_media_id(self) -> None:
        """
        Test if copying a local media creates media with original_media_id.
        """
        # create a media and make sure it's written to the file
        original_mxc = self.create_restricted_media(self.user)

        # Copy the original media
        channel = self.make_request(
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{self.hs.hostname}/{original_mxc.media_id}",
            access_token=self.user_tok,
            shorthand=False,
        )
        assert channel.code == 200, channel.json_body
        assert "content_uri" in channel.json_body
        copied_media_id = channel.json_body["content_uri"].split("/")[-1]

        # check if the copied media has the original media id field
        copied_media = self.get_success(
            self.hs.get_datastores().main.get_local_media(copied_media_id)
        )
        assert copied_media is not None
        assert copied_media.original_media_id is not None
        assert "synapse/media/local_content" in copied_media.original_media_id
        assert (
            self.generate_path_from_media_id(original_mxc.media_id)
            in copied_media.original_media_id
        )

    def test_copy_remote_media_with_original_media_id(self) -> None:
        """
        Test if copying a remote media creates media with original_media_id.
        """
        # Create remote media
        remote_server = "remoteserver.com"
        remote_file_id = "remote1"
        file_info = FileInfo(
            server_name=remote_server, file_id=remote_file_id, url_cache=True
        )

        assert isinstance(self.media_repository, MediaRepository)
        media_storage = self.media_repository.media_storage
        ctx = media_storage.store_into_file(file_info)
        (f, _) = self.get_success(ctx.__aenter__())
        f.write(SMALL_PNG)
        self.get_success(ctx.__aexit__(None, None, None))
        self.get_success(
            self.hs.get_datastores().main.store_cached_remote_media(
                origin=remote_server,
                media_id=remote_file_id,
                media_type="image/png",
                media_length=1,
                time_now_ms=self.clock.time_msec(),
                upload_name="test.png",
                filesystem_id=remote_file_id,
                sha256=remote_file_id,
                restricted=True,
            )
        )
        # Remote media is attached to a user profile
        remote_user_id = f"@remote-user:{remote_server}"
        self.get_success(
            self.hs.get_datastores().main.set_media_restricted_to_user_profile(
                remote_server, remote_file_id, remote_user_id
            )
        )
        restrictions = self.get_success(
            self.hs.get_datastores().main.get_media_restrictions(
                remote_server, remote_file_id
            )
        )
        assert restrictions is not None
        assert str(restrictions.profile_user_id) == remote_user_id

        # Make sure that the remote media is in cache
        cached_remote_media = self.get_success(
            self.hs.get_datastores().main.get_cached_remote_media(
                remote_server, remote_file_id
            )
        )
        assert cached_remote_media is not None
        assert cached_remote_media.media_id == remote_file_id
        assert cached_remote_media.filesystem_id == remote_file_id

        channel = self.make_request(
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{remote_server}/{remote_file_id}",
            access_token=self.user_tok,
        )
        # Remote media cannot get copied since `ensure_media_is_in_local_cache` checks if it's written in the
        # file and raise error if not.

        assert channel.code == 200, channel.json_body
        assert "content_uri" in channel.json_body
        copied_media_id = channel.json_body["content_uri"].split("/")[-1]

        # check if the copied media has the original media id field
        copied_media = self.get_success(
            self.hs.get_datastores().main.get_local_media(copied_media_id)
        )
        assert copied_media is not None
        assert copied_media.original_media_id is not None
        assert (
            f"synapse/media/remote_content/{remote_server}"
            in copied_media.original_media_id
        )
        assert (
            self.generate_path_from_media_id(remote_file_id)
            in copied_media.original_media_id
        )
