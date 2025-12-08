import os
from http import HTTPStatus

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media.filepath import MediaFilePaths
from synapse.media.media_repository import MediaRepository
from synapse.rest import admin
from synapse.rest.client import login, media, profile, room
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock
from synapse.util.stringutils import (
    random_string,
)

from tests import unittest


class PendingMediaDeletionTestCase(unittest.HomeserverTestCase):
    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
        profile.register_servlets,
    ]

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {}).update(
            {
                "msc3911": {
                    "enabled": True,
                    "purge_pending_unattached_media": True,
                },
            },
        )
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repository = hs.get_media_repository()
        self.store = hs.get_datastores().main

        self.user = self.register_user("user", "testpass")
        self.tok = self.login("user", "testpass")

        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def test_pending_media_deletion_success(self) -> None:
        """
        Test that media that is older than given time interval and not attached to any
        event or profile is deleted.
        """
        assert isinstance(self.media_repository, MediaRepository)

        # Create 2 media that is restricted but not attached to any event or profile
        random_content = bytes(random_string(24), "utf-8")
        channel = self.make_request(
            "POST",
            "_matrix/client/unstable/org.matrix.msc3911/media/upload?filename=test_1",
            random_content,
            self.tok,
            shorthand=False,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(24))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None
        media_1_id = mxc_uri_str.rsplit("/", 1)[-1]

        random_content = bytes(random_string(24), "utf-8")
        channel = self.make_request(
            "POST",
            "_matrix/client/unstable/org.matrix.msc3911/media/upload?filename=test_2",
            random_content,
            self.tok,
            shorthand=False,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(24))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None
        media_2_id = mxc_uri_str.rsplit("/", 1)[-1]

        # Prove that the media are written on the local media table
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_1_id)
        )
        assert uploaded_media is not None
        assert uploaded_media.attachments is None

        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_2_id)
        )
        assert uploaded_media is not None
        assert uploaded_media.attachments is None

        # Check if the file exists
        local_path_1 = self.filepaths.local_media_filepath(media_1_id)
        assert os.path.exists(local_path_1)
        local_path_2 = self.filepaths.local_media_filepath(media_2_id)
        assert os.path.exists(local_path_2)

        # Advance 25 hours to make the media eligible for deletion
        self.reactor.advance(25 * 60 * 60)

        # Check the deletion is completed
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_1_id)
        )
        assert uploaded_media is None

        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_2_id)
        )
        assert uploaded_media is None

        # Attempt to access media to check if media is deleted from file
        server_name = self.hs.hostname
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{server_name}/{media_1_id}",
            shorthand=False,
            access_token=self.tok,
        )
        assert channel.code == 404, (
            "Expected to receive a 404 on accessing deleted media: %s:%s"
            % (server_name, media_1_id)
        )

        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{server_name}/{media_2_id}",
            shorthand=False,
            access_token=self.tok,
        )
        assert channel.code == 404, (
            "Expected to receive a 404 on accessing deleted media: %s:%s"
            % (server_name, media_1_id)
        )

        # Test if the file is deleted
        assert os.path.exists(local_path_1) is False
        assert os.path.exists(local_path_2) is False

    def test_pending_media_deletion_not_deleted_if_attached(self) -> None:
        """
        Test that media that is attached to an event or profile is not deleted.
        """
        assert isinstance(self.media_repository, MediaRepository)

        # Create media via upload endpoint
        random_content = bytes(random_string(24), "utf-8")
        channel = self.make_request(
            "POST",
            "_matrix/client/unstable/org.matrix.msc3911/media/upload?filename=test_png_upload",
            random_content,
            self.tok,
            shorthand=False,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(24))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None

        # Attach the media to a profile
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": mxc_uri_str},
        )
        assert channel.code == HTTPStatus.OK
        assert channel.json_body == {}
        _, media_id = mxc_uri_str.rsplit("/", maxsplit=1)

        # Check if media is updated with restrictions field
        restrictions = self.get_success(
            self.store.get_media_restrictions(self.hs.hostname, media_id)
        )
        assert restrictions is not None, str(restrictions)
        assert restrictions.event_id is None
        assert restrictions.profile_user_id == UserID.from_string(self.user)

        # Advance 25 hours
        self.reactor.advance(25 * 60 * 60)

        # Check that media is not deleted
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_id)
        )
        assert uploaded_media is not None

    def test_pending_media_deletion_does_not_delete_unrestricted_media(self) -> None:
        """
        Test that unrestricted media should not be deleted.
        """
        assert isinstance(self.media_repository, MediaRepository)

        # Create unrestricted media via upload endpoint
        random_content = bytes(random_string(24), "utf-8")
        channel = self.make_request(
            "POST",
            "_matrix/media/v3/upload?filename=unrestricted",
            random_content,
            self.tok,
            shorthand=False,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(24))],
        )
        assert channel.code == 200, channel.json_body
        mxc_uri_str = channel.json_body.get("content_uri")
        assert mxc_uri_str is not None
        _, media_id = mxc_uri_str.rsplit("/", maxsplit=1)

        # Check if media is not restricted
        media_info = self.get_success(
            self.media_repository.store.get_local_media(media_id)
        )
        assert media_info is not None
        assert media_info.restricted is False

        # Advance 25 hours
        self.reactor.advance(25 * 60 * 60)

        # Check that media is not deleted
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(media_id)
        )
        assert uploaded_media is not None
