import io

from matrix_common.types.mxc_uri import MXCUri

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media.media_repository import MediaRepository
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import UserID
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
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config.update(
            {
                "experimental_features": {"msc3911_enabled": True},
            }
        )
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repository = hs.get_media_repository()
        self.store = hs.get_datastores().main

        self.user = self.register_user("user", "testpass")
        self.user_tok = self.login("user", "testpass")

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def test_pending_media_deletion(self) -> None:
        """
        Test that media that is older than 24 hours yet not attached to any event or profile is deleted.
        """
        assert isinstance(self.media_repository, MediaRepository)

        # Create media that is not attached to any event or profile
        random_content = bytes(random_string(24), "utf-8")
        mxc_uri_1: MXCUri = self.get_success(
            self.media_repository.create_or_update_content(
                media_type="text/plain",
                upload_name=None,
                content=io.BytesIO(random_content),
                content_length=len(random_content),
                auth_user=UserID.from_string(self.user),
            )
        )

        random_content = bytes(random_string(24), "utf-8")
        mxc_uri_2: MXCUri = self.get_success(
            self.media_repository.create_or_update_content(
                media_type="text/plain",
                upload_name=None,
                content=io.BytesIO(random_content),
                content_length=len(random_content),
                auth_user=UserID.from_string(self.user),
            )
        )

        # Prove that the media is written on the local media table
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(mxc_uri_1.media_id)
        )
        assert uploaded_media is not None
        assert uploaded_media.attachments is None

        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(mxc_uri_2.media_id)
        )
        assert uploaded_media is not None
        assert uploaded_media.attachments is None

        # Advance 25 hours to make the media eligible for deletion
        self.reactor.advance(25 * 60 * 60)

        # Check the deletion is completed
        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(mxc_uri_1.media_id)
        )
        assert uploaded_media is None

        uploaded_media = self.get_success(
            self.media_repository.store.get_local_media(mxc_uri_2.media_id)
        )
        assert uploaded_media is None
