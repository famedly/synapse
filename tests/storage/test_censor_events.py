import io
import os
import time
from http import HTTPStatus
from typing import Optional, Tuple

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media.media_repository import (
    MediaRepository,
)
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests.test_utils import SMALL_PNG
from tests.unittest import HomeserverTestCase


class MediaDeletionOnRedactionCensorshipTests(HomeserverTestCase):
    """Tests for deleting media attached to redacted events."""

    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]
    use_isolated_media_paths = True

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911": {"enabled": True}})
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.store = hs.get_datastores().main
        self.media_repo = hs.get_media_repository()
        self.bad_user = self.register_user("bad_user", "hackme")
        self.bad_user_tok = self.login("bad_user", "hackme")
        self.user = self.register_user("user", "pass")
        self.user_tok = self.login("user", "pass")
        self.admin = self.register_user("admin", "admin_pass", admin=True)
        self.admin_tok = self.login("admin", "admin_pass")
        self.room = self.helper.create_room_as(
            room_creator=self.admin, tok=self.admin_tok
        )

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def _redact_event(
        self,
        access_token: str,
        room_id: str,
        event_id: str,
        expect_code: int = 200,
        with_relations: Optional[list[str]] = None,
        content: Optional[JsonDict] = None,
    ) -> JsonDict:
        """Helper function to send a redaction event.

        Returns the json body.
        """
        path = "/_matrix/client/r0/rooms/%s/redact/%s" % (room_id, event_id)

        request_content = content or {}
        if with_relations:
            request_content["org.matrix.msc3912.with_relations"] = with_relations

        channel = self.make_request(
            "POST", path, request_content, access_token=access_token
        )
        assert channel.code == expect_code, channel.json_body
        return channel.json_body

    def _create_test_resource(self) -> Tuple[list[str], list[str]]:
        event_ids = []
        media_ids = []
        self.helper.join(self.room, self.user, tok=self.user_tok)
        self.helper.join(self.room, self.bad_user, tok=self.bad_user_tok)

        for _ in range(3):
            # Create restricted media
            mxc_uri = self.get_success(
                self.media_repo.create_or_update_content(
                    "image/png",
                    "test_png_upload",
                    io.BytesIO(SMALL_PNG),
                    67,
                    UserID.from_string(self.bad_user),
                    restricted=True,
                )
            )
            # Make sure media is saved
            assert mxc_uri is not None
            assert isinstance(self.media_repo, MediaRepository)
            media_path = self.media_repo.filepaths.local_media_filepath(
                mxc_uri.media_id
            )
            self.assertTrue(os.path.exists(media_path))
            assert self.get_success(self.store.get_local_media(mxc_uri.media_id))
            media_ids.append(mxc_uri.media_id)

            # Bad user create events with media attached
            channel = self.make_request(
                "PUT",
                f"/rooms/{self.room}/send/m.room.message/{str(time.time())}?org.matrix.msc3911.attach_media={str(mxc_uri)}",
                content={"msgtype": "m.text", "body": "Hi, this is a message"},
                access_token=self.bad_user_tok,
            )
            assert channel.code == HTTPStatus.OK, channel.json_body
            assert "event_id" in channel.json_body
            event_id = channel.json_body["event_id"]
            event_ids.append(event_id)

            # Check media restrictions field has proper event_id
            restrictions = self.get_success(
                self.hs.get_datastores().main.get_media_restrictions(
                    mxc_uri.server_name, mxc_uri.media_id
                )
            )
            assert restrictions is not None, str(restrictions)
            assert restrictions.event_id == event_id
        return media_ids, event_ids

    def test_get_attached_media_ids(self) -> None:
        """Test db function `get_attached_media_ids`"""
        # Create events with media attached
        media_ids, event_ids = self._create_test_resource()

        # Check if `get_attached_media_ids` can get media ids attached to an event
        for event_id in event_ids:
            media_ids = self.get_success(self.store.get_attached_media_ids(event_id))
            assert len(media_ids) == 1

    def test_redacting_media_deletes_attached_media(self) -> None:
        """Test that censor_redactions looping call(every 5 minutes) deletes media that has been
        redacted before 7 days.
        """
        # Create events with media attached
        media_ids, event_ids = self._create_test_resource()

        # Redact the events
        for event_id in event_ids:
            self._redact_event(
                self.admin_tok,
                self.room,
                event_id,
                expect_code=200,
            )
            # Confirm the events redaction
            event_dict = self.helper.get_event(self.room, event_id, self.admin_tok)
            assert "redacted_because" in event_dict, event_dict

        # Fast forward 7 days and 6 minutes to make sure the censor_redactions looping
        # call detects the events are eligible for censorship.
        self.reactor.advance(7 * 24 * 60 * 60 + 6 * 60)

        # Check if the media is deleted from storage.
        for media_id in media_ids:
            media = self.get_success(self.store.get_local_media(media_id))
            assert media is None
            assert isinstance(self.media_repo, MediaRepository)
            assert not os.path.exists(
                self.media_repo.filepaths.local_media_filepath(media_id)
            )

    def test_normal_users_lose_access_to_media_right_after_redaction(self) -> None:
        """Test that normal users lose access to media after the event they
        were attached to has been redacted.
        """
        # Create events with media attached
        media_ids, event_ids = self._create_test_resource()

        # Redact the bad user's events
        for event_id in event_ids:
            self._redact_event(
                self.admin_tok,
                self.room,
                event_id,
                expect_code=200,
            )
            event_dict = self.helper.get_event(self.room, event_id, self.admin_tok)
            self.assertIn("redacted_because", event_dict, event_dict)

        # Normal user trying to access redacted media should get 404
        for media_id in media_ids:
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}",
                shorthand=False,
                access_token=self.user_tok,
            )
            assert channel.code == 404, channel.json_body

    def test_moderators_still_have_access_to_media_after_redaction_until_permanent_deletion(
        self,
    ) -> None:
        """Test that users with moderator privileges still have access to media
        after the event they were attached to has been redacted.
        """
        # Create events with media attached
        media_ids, event_ids = self._create_test_resource()

        # Redact the bad user's events
        for event_id in event_ids:
            self._redact_event(
                self.admin_tok,
                self.room,
                event_id,
                expect_code=200,
            )
            event_dict = self.helper.get_event(self.room, event_id, self.admin_tok)
            self.assertIn("redacted_because", event_dict, event_dict)

        # User with moderator privileges still have access to redacted media
        for media_id in media_ids:
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}?allow_redacted_media=true",
                shorthand=False,
                access_token=self.admin_tok,
            )
            assert channel.code == 200, channel.json_body

        # After 7 days and 6 minutes, media that are attached to the redacted events
        # should be permanatly deleted from disk and moderators no longer have access to
        # them
        self.reactor.advance(7 * 24 * 60 * 60 + 6 * 60)

        for media_id in media_ids:
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}?allow_redacted_media=true",
                shorthand=False,
                access_token=self.admin_tok,
            )
            assert channel.code == 404, channel.json_body
