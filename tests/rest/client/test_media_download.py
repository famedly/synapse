#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2022 The Matrix.org Foundation C.I.C.
# Copyright (C) 2024 New Vector, Ltd
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
# [This file includes modifications made by New Vector Limited]
#
#
import io

from matrix_common.types.mxc_uri import MXCUri
from PIL import Image as Image

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock
from tests.unittest import override_config

from tests import unittest
from tests.test_utils import SMALL_PNG

from synapse.api.constants import (
    ApprovalNoticeMedium,
    EventContentFields,
    EventTypes,
    LoginType,
    UserTypes,
)
class RestrictedResourceDownloadTestCase(unittest.HomeserverTestCase):
    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config.update({
            "experimental_features": {"msc3911_enabled": True},
        })
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.repo = hs.get_media_repository()
        self.store = hs.get_datastores().main
        self.creator = self.register_user("creator", "testpass")
        self.creator_tok = self.login("creator", "testpass")
        self.other_user = self.register_user("random_user", "testpass")
        self.other_user_tok = self.login("random_user", "testpass")

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def _create_media(self, user: str) -> MXCUri:
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

    def test_user_download_local_media_unrestricted(self):
        # create unrestricted resource
        content_mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(self.other_user),
                restricted=False,
            )
        )
        # user download unrestricted resource
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{content_mxc_uri.media_id}/test_png_upload",
            access_token=self.creator_tok,
        )
        assert channel.code == 200

    def test_user_download_local_media_restricted_but_pending_state(self):
        mxc_uri = self._create_media(self.creator)
        # user download pending resource
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.creator_tok,
        )
        assert channel.code == 200

    def test_other_user_download_local_media_restricted_but_pending_state(self):
        mxc_uri = self._create_media(self.creator)
        # user download pending resource
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.other_user_tok,
        )
        assert channel.code == 404

    def test_user_download_local_media_attached_to_user_profile_success(self):
        mxc_uri = self._create_media(self.creator)
        self.get_success(self.store.set_media_restrictions(mxc_uri.server_name, mxc_uri.media_id, {"restrictions": {"profile_user_id": self.creator}}))
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.creator_tok,
        )
        assert channel.code == 200

    @override_config(
        {
            "limit_profile_requests_to_users_who_share_rooms": True,
        }
    )
    def test_user_download_local_media_attached_to_user_profile_failure(self):
        # with additional config, when two users share no room, users couldn't see each other's profile.
        mxc_uri = self._create_media(self.creator)
        self.get_success(self.store.set_media_restrictions(mxc_uri.server_name, mxc_uri.media_id, {"restrictions": {"profile_user_id": self.creator}}))
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.other_user_tok,
        )
        assert channel.code == 403

    def test_user_download_local_media_attached_to_message_event_success(self):
        mxc_uri = self._create_media(self.creator)
        room = self.helper.create_room_as(
            self.creator, tok=self.creator_tok
        )
        join = self.helper.join(room, self.other_user, tok=self.other_user_tok)
        # the process of attaching event_id to media is not there yet, so manually attaching here
        image = {
                "body": "filename.jpg",
                "info": {
                    "h": 398,
                    "mimetype": "image/jpeg",
                    "size": 31037,
                    "w": 394
                },
                "msgtype": "m.image",
                "url": str(mxc_uri),
            }
        event_id = self.helper.send_event(
            room, "m.room.message", content=image, tok=self.creator_tok, expect_code=200
        )
        self.get_success(self.store.set_media_restrictions(mxc_uri.server_name, mxc_uri.media_id, {"restrictions": {"event_id": event_id}}))

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.other_user_tok,
        )
        assert channel.code == 200

    def test_user_download_local_media_attached_to_message_event_failure(self):
        mxc_uri = self._create_media(self.creator)
        room = self.helper.create_room_as(
            self.creator, tok=self.creator_tok
        )
        # set room history_visibility to joined
        self.helper.send_state(
            room_id=room,
            event_type="m.room.history_visibility",
            body={"history_visibility": "joined"},
            tok=self.creator_tok,
        )
        self.helper.join(room, self.other_user, tok=self.other_user_tok)
        # the process of attaching event_id to media is not there yet, so manually attaching here
        image = {
                "body": "filename.jpg",
                "info": {
                    "h": 398,
                    "mimetype": "image/jpeg",
                    "size": 31037,
                    "w": 394
                },
                "msgtype": "m.image",
                "url": str(mxc_uri),
            }
        event_id = self.helper.send_event(
            room, "m.room.message", content=image, tok=self.creator_tok, expect_code=200
        )
        self.get_success(self.store.set_media_restrictions(mxc_uri.server_name, mxc_uri.media_id, {"restrictions": {"event_id": event_id}}))

        # now the other user get kicked out of the room.
        channel = self.make_request(
                "POST",
                f"/_matrix/client/r0/rooms/{room}/kick",
                content={"reason": "for test", "user_id": self.other_user},
                access_token=self.creator_tok,
            )
        assert channel.code == 200, channel.result
        
        # other user try to download media
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}/test_png_upload",
            access_token=self.other_user_tok,
        )
        assert channel.code == 403

    def test_user_download_local_media_attached_to_state_event_success(self):
        pass

    def test_user_download_local_media_attached_to_state_event_failure(self):
        pass
