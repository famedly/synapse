from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import SynapseError
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest


class MediaAttachmentStorageTestCase(unittest.HomeserverTestCase):
    """
    Test that storing and retrieving media restrictions works as expected

    Specifically, we test that storing media restrictions are then retrievable, that
    our MediaRestrictions object is created as expected, and that a given piece of media
     can not be set twice(no overwriting of values)
    """

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.server_name = self.hs.config.server.server_name

    def test_store_and_retrieve_media_restrictions_by_event_id(self) -> None:
        event_id = "$random_event_id"
        media_id = random_string(24)
        self.get_success_or_raise(
            self.store.set_media_restricted_to_event_id(
                self.server_name, media_id, event_id
            )
        )

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is not None
        assert retrieved_restrictions.event_id == event_id
        assert retrieved_restrictions.profile_user_id is None

    def test_store_and_retrieve_media_restrictions_by_profile_user_id(self) -> None:
        user_id = "@frank:test"
        media_id = random_string(24)
        self.get_success_or_raise(
            self.store.set_media_restricted_to_user_profile(
                self.server_name, media_id, user_id
            )
        )

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is not None
        assert retrieved_restrictions.event_id is None
        assert retrieved_restrictions.profile_user_id == user_id

    def test_retrieve_media_without_restrictions(self) -> None:
        """Test that retrieving non-existent restrictions does not raise an exception"""
        media_id = random_string(24)

        retrieved_restrictions = self.get_success_or_raise(
            self.store.get_media_restrictions(self.server_name, media_id)
        )
        assert retrieved_restrictions is None

    def test_setting_media_restriction_twice_errors(
        self,
    ) -> None:
        """Setting media restrictions on a single piece of media TWICE is not allowed.
        Test that it errors
        """
        media_id = random_string(24)
        event_id = "$something_hashy_doesnt_matter"

        self.get_success(
            self.store.set_media_restricted_to_event_id(
                self.server_name, media_id, event_id
            )
        )

        existing_media_restrictions = self.get_success(
            self.store.get_media_restrictions(
                self.server_name,
                media_id,
            )
        )
        assert existing_media_restrictions is not None
        assert existing_media_restrictions.profile_user_id is None
        assert existing_media_restrictions.event_id == event_id

        new_event_id = "$something_newer_but_still_hashy"
        self.get_failure(
            self.store.set_media_restricted_to_event_id(
                self.server_name, media_id, new_event_id
            ),
            SynapseError,
        )

        # Verify that even with the error, nothing has actually changed
        verify_media_restrictions = self.get_success(
            self.store.get_media_restrictions(
                self.server_name,
                media_id,
            )
        )
        assert verify_media_restrictions is not None
        assert (
            verify_media_restrictions.profile_user_id
            == existing_media_restrictions.profile_user_id
        )
        assert (
            verify_media_restrictions.event_id == existing_media_restrictions.event_id
        )
