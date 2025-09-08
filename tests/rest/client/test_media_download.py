#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2025 The Matrix.org Foundation C.I.C.
# Copyright (C) 2025 Famedly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#

import io
from typing import Optional

from matrix_common.types.mxc_uri import MXCUri

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    Membership,
)
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG
from tests.unittest import override_config


class RestrictedResourceDownloadTestCase(unittest.HomeserverTestCase):
    """
    Test the `/download` media endpoint for restricted media.

    Something to note: rooms here will be set to room history visibility of 'joined'
    at a minimum, or the media would be visible by default
    """

    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911_enabled": True})
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.repo = hs.get_media_repository()
        self.store = hs.get_datastores().main
        self.creator = self.register_user("creator", "testpass")
        self.creator_tok = self.login("creator", "testpass")
        self.other_user = self.register_user("random_user", "testpass")
        self.other_user_tok = self.login("random_user", "testpass")
        self.other_profile_test_user = self.register_user(
            "profile_test_user", "testpass"
        )
        self.other_profile_test_user_tok = self.login("profile_test_user", "testpass")

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def _create_restricted_media(self, user: str) -> MXCUri:
        mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(user),
                restricted=True,
            )
        )
        return mxc_uri

    def fetch_media(
        self,
        mxc_uri: MXCUri,
        access_token: Optional[str] = None,
        expected_code: int = 200,
    ) -> None:
        """
        Test retrieving the media. We do not care about the content of the media, just
        that the response is correct
        """
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{mxc_uri.server_name}/{mxc_uri.media_id}",
            access_token=access_token or self.creator_tok,
        )
        assert channel.code == expected_code, channel.code

    def test_user_download_local_media_unrestricted(self) -> None:
        """Test that unrestricted media is not affected"""
        mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(self.other_user),
                restricted=False,
            )
        )
        # The assertion of 200 as a response code is part of the function
        self.fetch_media(mxc_uri)
        self.fetch_media(mxc_uri, access_token=self.other_user_tok)

    def test_download_local_media_restricted_but_pending_state(self) -> None:
        """Test originating user can access media even though it is not attached"""
        mxc_uri = self._create_restricted_media(self.creator)
        # The creator user can see their own media
        self.fetch_media(mxc_uri)
        # But another user can not
        self.fetch_media(mxc_uri, access_token=self.other_user_tok, expected_code=403)

    def test_user_download_local_media_attached_to_user_profile_success(self) -> None:
        """Test retrieving media attached to user's profile"""
        prime_mxc_uri = self._create_restricted_media(self.creator)
        other_mxc_uri = self._create_restricted_media(self.other_profile_test_user)
        # Inject directly to the database, we are not here to test the profile endpoint
        self.get_success(
            self.store.set_media_restricted_to_user_profile(
                prime_mxc_uri.server_name,
                prime_mxc_uri.media_id,
                self.creator,
            )
        )
        self.get_success(
            self.store.set_media_restricted_to_user_profile(
                other_mxc_uri.server_name,
                other_mxc_uri.media_id,
                self.other_profile_test_user,
            )
        )

        # Should be able to see their own
        self.fetch_media(prime_mxc_uri, access_token=self.creator_tok)
        self.fetch_media(other_mxc_uri, access_token=self.other_profile_test_user_tok)

        # Should be able to see each others
        self.fetch_media(other_mxc_uri, access_token=self.creator_tok)
        self.fetch_media(prime_mxc_uri, access_token=self.other_profile_test_user_tok)

    @override_config(
        {
            "limit_profile_requests_to_users_who_share_rooms": True,
        }
    )
    def test_user_download_local_media_attached_to_user_profile_failure(self) -> None:
        """
        Test that limiting profile requests works as expected. Specifically, that users
        that are not sharing a room can not see profile avatars
        """

        prime_mxc_uri = self._create_restricted_media(self.creator)
        other_mxc_uri = self._create_restricted_media(self.other_profile_test_user)
        # Inject directly to the database, we are not here to test the profile endpoint
        self.get_success(
            self.store.set_media_restricted_to_user_profile(
                prime_mxc_uri.server_name,
                prime_mxc_uri.media_id,
                self.creator,
            )
        )
        self.get_success(
            self.store.set_media_restricted_to_user_profile(
                other_mxc_uri.server_name,
                other_mxc_uri.media_id,
                self.other_profile_test_user,
            )
        )

        # Should be able to see their own
        self.fetch_media(prime_mxc_uri, access_token=self.creator_tok)
        self.fetch_media(other_mxc_uri, access_token=self.other_profile_test_user_tok)

        # Should NOT be able to see each others, since the limitation setting is enabled
        self.fetch_media(
            other_mxc_uri, access_token=self.creator_tok, expected_code=403
        )
        self.fetch_media(
            prime_mxc_uri,
            access_token=self.other_profile_test_user_tok,
            expected_code=403,
        )

    def test_user_download_local_media_attached_to_message_event_success(self) -> None:
        """Test that can local media attached to image event can be viewed"""
        mxc_uri = self._create_restricted_media(self.creator)
        room_id = self.helper.create_room_as(self.creator, tok=self.creator_tok)

        # set room history_visibility to joined, otherwise it will be 'shared'
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.creator_tok,
        )

        _ = self.helper.join(room_id, self.other_user, tok=self.other_user_tok)
        # TODO: verify this file info is legit, because it does not match SMALL_PNG. It
        #  seems to work tho, oddly
        image = {
            "body": "test_png_upload",
            "info": {"h": 1, "mimetype": "image/png", "size": 67, "w": 1},
            "msgtype": "m.image",
            "url": str(mxc_uri),
        }
        json_body = self.helper.send_event(
            room_id,
            "m.room.message",
            content=image,
            tok=self.creator_tok,
            expect_code=200,
            attach_media_mxc=str(mxc_uri),
        )
        assert "event_id" in json_body

        # Both users should be able to see the event
        self.fetch_media(mxc_uri)
        self.fetch_media(mxc_uri, access_token=self.other_user_tok)

    def test_user_download_local_media_attached_to_message_event_failure(self) -> None:
        """Test that can local media attached to image event can be restricted"""
        mxc_uri = self._create_restricted_media(self.creator)
        room_id = self.helper.create_room_as(self.creator, tok=self.creator_tok)

        # set room history_visibility to joined
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.creator_tok,
        )

        image = {
            "body": "test_png_upload",
            "info": {"h": 1, "mimetype": "image/png", "size": 67, "w": 1},
            "msgtype": "m.image",
            "url": str(mxc_uri),
        }
        json_body = self.helper.send_event(
            room_id,
            "m.room.message",
            content=image,
            tok=self.creator_tok,
            expect_code=200,
            attach_media_mxc=str(mxc_uri),
        )
        assert "event_id" in json_body

        # Specifically, join the user AFTER sending the attaching message
        self.helper.join(room_id, self.other_user, tok=self.other_user_tok)

        self.fetch_media(mxc_uri)
        # The other user was not in the room at the time the image was sent, so this
        # should fail.
        self.fetch_media(mxc_uri, access_token=self.other_user_tok, expected_code=403)

    def test_user_download_local_media_attached_to_state_event_success(self) -> None:
        """Test that a simple membership avatar is viewable when appropriate"""
        mxc_uri = self._create_restricted_media(self.creator)
        room_id = self.helper.create_room_as(self.creator, tok=self.creator_tok)

        # set room history_visibility to joined
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.creator_tok,
        )

        _ = self.helper.join(room_id, self.other_user, tok=self.other_user_tok)

        membership_content = {
            EventContentFields.MEMBERSHIP: Membership.JOIN,
            "avatar_url": str(mxc_uri),
        }
        json_body = self.helper.send_state(
            room_id,
            EventTypes.Member,
            body=membership_content,
            tok=self.creator_tok,
            expect_code=200,
            state_key=self.creator,
            attach_media_mxc=str(mxc_uri),
        )
        assert "event_id" in json_body

        # Both users should be able to see the media
        self.fetch_media(mxc_uri)
        self.fetch_media(mxc_uri, access_token=self.other_user_tok)

    def test_user_download_local_media_attached_to_state_event_failure(self) -> None:
        """Test that a simple membership avatar is restricted when appropriate"""
        mxc_uri = self._create_restricted_media(self.creator)
        room_id = self.helper.create_room_as(self.creator, tok=self.creator_tok)
        # set room history_visibility to joined
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.creator_tok,
        )

        membership_content = {
            EventContentFields.MEMBERSHIP: Membership.JOIN,
            "avatar_url": str(mxc_uri),
        }
        json_body = self.helper.send_state(
            room_id,
            EventTypes.Member,
            body=membership_content,
            tok=self.creator_tok,
            expect_code=200,
            state_key=self.creator,
            attach_media_mxc=str(mxc_uri),
        )
        assert "event_id" in json_body

        _ = self.helper.join(room_id, self.other_user, tok=self.other_user_tok)

        self.fetch_media(mxc_uri)
        self.fetch_media(mxc_uri, access_token=self.other_user_tok, expected_code=403)
