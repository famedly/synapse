import io
from typing import Dict

from matrix_common.types.mxc_uri import MXCUri

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.errors import SynapseError
from synapse.rest import admin
from synapse.rest.client import login, media
from synapse.server import HomeServer
from synapse.storage.databases.main.media_repository import MediaRestrictions
from synapse.types import JsonDict, UserID
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import SMALL_PNG


class MediaAttachmentStorageTestCase(unittest.HomeserverTestCase):
    """Test that storing and retrieving media restrictions works as expected"""

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.server_name = self.hs.config.server.server_name

    def test_store_and_retrieve_media_restrictions_by_event_id(self) -> None:
        event_id = "$random_event_id"
        media_restrictions = {"restrictions": {"event_id": event_id}}
        media_id = random_string(24)
        self.get_success_or_raise(
            self.store.set_media_restrictions(
                self.server_name, media_id, media_restrictions
            )
        )

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is not None
        assert retrieved_restrictions.event_id == event_id
        assert retrieved_restrictions.profile_user_id is None

    def test_store_and_retrieve_media_restrictions_by_profile_user_id(self) -> None:
        user_id = UserID.from_string("@frank:test")
        media_restrictions = {"restrictions": {"profile_user_id": user_id.to_string()}}
        media_id = random_string(24)
        self.get_success_or_raise(
            self.store.set_media_restrictions(
                self.server_name, media_id, media_restrictions
            )
        )

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is not None
        assert retrieved_restrictions.event_id is None
        assert retrieved_restrictions.profile_user_id == user_id

    def test_retrieve_media_without_restrictions(self) -> None:
        media_id = random_string(24)

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is None


class MediaPendingAttachmentTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        media.register_servlets,
    ]

    def default_config(self) -> JsonDict:
        config = super().default_config()
        return config

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.server_name = self.hs.config.server.server_name

        self.user = self.register_user("frank", "password")
        self.tok = self.login("frank", "password")

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        # The old endpoints are not loaded with the register_servlets above
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def test_setting_media_restriction_twice_errors(
        self,
    ) -> None:
        """Setting media restrictions on a single piece of media TWICE is not allowed.
        Test that it errors
        """
        upload_result = self.helper.upload_media(SMALL_PNG, tok=self.tok)
        assert upload_result.get("content_uri") is not None

        content_uri: str = upload_result["content_uri"]
        # We can split the content_uri on the last "/" and the rest is the media_id
        media_id = content_uri.rsplit("/", maxsplit=1)[1]

        event_id = "$something_hashy_doesnt_matter"
        media_restrictions = {"restrictions": {"event_id": event_id}}
        self.get_success(
            self.store.set_media_restrictions(
                self.server_name, media_id, media_restrictions
            )
        )

        existing_media_restrictions = self.get_success(
            self.store.get_media_restrictions(
                self.server_name,
                media_id,
            )
        )
        assert existing_media_restrictions is not None

        self.get_failure(
            self.store.set_media_restrictions(
                self.server_name, media_id, media_restrictions
            ),
            SynapseError,
        )


class MediaAttachmentFlowTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        media.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.server_name = self.hs.config.server.server_name
        self.media_repo = self.hs.get_media_repository()

        self.user = self.register_user("frank", "password")
        self.tok = self.login("frank", "password")

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        # The old endpoints are not loaded with the register_servlets above
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def create_media(self) -> MXCUri:
        content = io.BytesIO(SMALL_PNG)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                content,
                67,
                UserID.from_string("@user_id:whatever.org"),
                restricted=True,
            )
        )
        return content_uri

    def test_flow(self) -> None:
        """Example flow of storing media data and retrieving it from the database"""
        # Create media by using create_or_update_content() helper. This will likely be
        # on the new `/create` and `/upload` endpoints for msc3911.

        # set actual restrictions using storage method `set_media_restrictions()`

        # use `get_local_media()` to retrieve the data

        mxc_uri = self.create_media()
        media_id = mxc_uri.media_id
        assert media_id

        local_media_object = self.get_success(self.store.get_local_media(media_id))
        assert local_media_object
        assert local_media_object.restricted is True

        # This one is why we are here, it doesn't exist yet
        assert local_media_object.attachments is None

        event_id = "$event_id_hash_goes_here"
        self.get_success(
            self.store.set_media_restrictions(
                self.server_name,
                media_id,
                {"restrictions": {"event_id": event_id}},
            )
        )

        # Retrieve the data and make sure the restrictions are there
        local_media_object = self.get_success(self.store.get_local_media(media_id))
        assert local_media_object

        assert local_media_object.restricted is True
        # This one is why we are here, it's here this time. Yay!
        assert isinstance(local_media_object.attachments, MediaRestrictions)
        assert local_media_object.attachments.event_id == event_id
