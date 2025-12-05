#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2019 The Matrix.org Foundation C.I.C.
# Copyright (C) 2023 New Vector, Ltd
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
import os
import time
from http import HTTPStatus
from typing import List, Optional, Tuple

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.auth.base import BaseAuth
from synapse.api.constants import EventTypes, RelationTypes
from synapse.api.room_versions import RoomVersion, RoomVersions
from synapse.media.media_repository import (
    MediaRepository,
)
from synapse.rest import admin
from synapse.rest.client import login, media, room, sync
from synapse.server import HomeServer
from synapse.storage._base import db_to_json
from synapse.storage.database import LoggingTransaction
from synapse.types import JsonDict, Requester, UserID
from synapse.util import Clock

from tests.test_utils import SMALL_PNG
from tests.unittest import HomeserverTestCase, override_config


class RedactionsTestCase(HomeserverTestCase):
    """Tests that various redaction events are handled correctly"""

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        config["rc_message"] = {"per_second": 0.2, "burst_count": 10}
        config["rc_admin_redaction"] = {"per_second": 1, "burst_count": 100}

        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # register a couple of users
        self.mod_user_id = self.register_user("user1", "pass")
        self.mod_access_token = self.login("user1", "pass")
        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")

        # Create a room
        self.room_id = self.helper.create_room_as(
            self.mod_user_id, tok=self.mod_access_token
        )

        # Invite the other user
        self.helper.invite(
            room=self.room_id,
            src=self.mod_user_id,
            tok=self.mod_access_token,
            targ=self.other_user_id,
        )
        # The other user joins
        self.helper.join(
            room=self.room_id, user=self.other_user_id, tok=self.other_access_token
        )

    def _redact_event(
        self,
        access_token: str,
        room_id: str,
        event_id: str,
        expect_code: int = 200,
        with_relations: Optional[List[str]] = None,
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
        self.assertEqual(channel.code, expect_code)
        return channel.json_body

    def _sync_room_timeline(self, access_token: str, room_id: str) -> List[JsonDict]:
        channel = self.make_request("GET", "sync", access_token=access_token)
        self.assertEqual(channel.code, 200)
        room_sync = channel.json_body["rooms"]["join"][room_id]
        return room_sync["timeline"]["events"]

    def test_redact_event_as_moderator(self) -> None:
        # as a regular user, send a message to redact
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        msg_id = b["event_id"]

        # as the moderator, send a redaction
        b = self._redact_event(self.mod_access_token, self.room_id, msg_id)
        redaction_id = b["event_id"]

        # now sync
        timeline = self._sync_room_timeline(self.mod_access_token, self.room_id)

        # the last event should be the redaction
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], msg_id)

        # and the penultimate should be the redacted original
        self.assertEqual(timeline[-2]["event_id"], msg_id)
        self.assertEqual(timeline[-2]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-2]["content"], {})

    def test_redact_event_as_normal(self) -> None:
        # as a regular user, send a message to redact
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        normal_msg_id = b["event_id"]

        # also send one as the admin
        b = self.helper.send(room_id=self.room_id, tok=self.mod_access_token)
        admin_msg_id = b["event_id"]

        # as a normal, try to redact the admin's event
        self._redact_event(
            self.other_access_token, self.room_id, admin_msg_id, expect_code=403
        )

        # now try to redact our own event
        b = self._redact_event(self.other_access_token, self.room_id, normal_msg_id)
        redaction_id = b["event_id"]

        # now sync
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)

        # the last event should be the redaction of the normal event
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], normal_msg_id)

        # the penultimate should be the unredacted one from the admin
        self.assertEqual(timeline[-2]["event_id"], admin_msg_id)
        self.assertNotIn("redacted_by", timeline[-2]["unsigned"])
        self.assertTrue(timeline[-2]["content"]["body"], {})

        # and the antepenultimate should be the redacted normal
        self.assertEqual(timeline[-3]["event_id"], normal_msg_id)
        self.assertEqual(timeline[-3]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-3]["content"], {})

    def test_redact_nonexistent_event(self) -> None:
        # control case: an existing event
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        msg_id = b["event_id"]
        b = self._redact_event(self.other_access_token, self.room_id, msg_id)
        redaction_id = b["event_id"]

        # room moderators can send redactions for non-existent events
        self._redact_event(self.mod_access_token, self.room_id, "$zzz")

        # ... but normals cannot
        self._redact_event(
            self.other_access_token, self.room_id, "$zzz", expect_code=404
        )

        # when we sync, we should see only the valid redaction
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], msg_id)

        # and the penultimate should be the redacted original
        self.assertEqual(timeline[-2]["event_id"], msg_id)
        self.assertEqual(timeline[-2]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-2]["content"], {})

    def test_redact_create_event(self) -> None:
        # control case: an existing event
        b = self.helper.send(room_id=self.room_id, tok=self.mod_access_token)
        msg_id = b["event_id"]
        self._redact_event(self.mod_access_token, self.room_id, msg_id)

        # sync the room, to get the id of the create event
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)
        create_event_id = timeline[0]["event_id"]

        # room moderators cannot send redactions for create events
        self._redact_event(
            self.mod_access_token, self.room_id, create_event_id, expect_code=403
        )

        # and nor can normals
        self._redact_event(
            self.other_access_token, self.room_id, create_event_id, expect_code=403
        )

    def test_redact_event_as_moderator_ratelimit(self) -> None:
        """Tests that the correct ratelimiting is applied to redactions"""

        message_ids = []
        # as a regular user, send messages to redact
        for _ in range(20):
            b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
            message_ids.append(b["event_id"])
            self.reactor.advance(10)  # To get around ratelimits

        # as the moderator, send a bunch of redactions
        for msg_id in message_ids:
            # These should all succeed, even though this would be denied by
            # the standard message ratelimiter
            self._redact_event(self.mod_access_token, self.room_id, msg_id)

    @override_config({"experimental_features": {"msc3912_enabled": True}})
    def test_redact_relations_with_types(self) -> None:
        """Tests that we can redact the relations of an event of specific types
        at the same time as the event itself.
        """
        # Send a root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "hello"},
            tok=self.mod_access_token,
        )
        root_event_id = res["event_id"]

        # Send an edit to this root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "body": " * hello world",
                "m.new_content": {
                    "body": "hello world",
                    "msgtype": "m.text",
                },
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.REPLACE,
                },
                "msgtype": "m.text",
            },
            tok=self.mod_access_token,
        )
        edit_event_id = res["event_id"]

        # Also send a threaded message whose root is the same as the edit's.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message 1",
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.THREAD,
                },
            },
            tok=self.mod_access_token,
        )
        threaded_event_id = res["event_id"]

        # Also send a reaction, again with the same root.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Reaction,
            content={
                "m.relates_to": {
                    "rel_type": RelationTypes.ANNOTATION,
                    "event_id": root_event_id,
                    "key": "👍",
                }
            },
            tok=self.mod_access_token,
        )
        reaction_event_id = res["event_id"]

        # Redact the root event, specifying that we also want to delete events that
        # relate to it with m.replace.
        self._redact_event(
            self.mod_access_token,
            self.room_id,
            root_event_id,
            with_relations=[
                RelationTypes.REPLACE,
                RelationTypes.THREAD,
            ],
        )

        # Check that the root event got redacted.
        event_dict = self.helper.get_event(
            self.room_id, root_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the edit got redacted.
        event_dict = self.helper.get_event(
            self.room_id, edit_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the threaded message got redacted.
        event_dict = self.helper.get_event(
            self.room_id, threaded_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the reaction did not get redacted.
        event_dict = self.helper.get_event(
            self.room_id, reaction_event_id, self.mod_access_token
        )
        self.assertNotIn("redacted_because", event_dict, event_dict)

    @override_config({"experimental_features": {"msc3912_enabled": True}})
    def test_redact_all_relations(self) -> None:
        """Tests that we can redact all the relations of an event at the same time as the
        event itself.
        """
        # Send a root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "hello"},
            tok=self.mod_access_token,
        )
        root_event_id = res["event_id"]

        # Send an edit to this root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "body": " * hello world",
                "m.new_content": {
                    "body": "hello world",
                    "msgtype": "m.text",
                },
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.REPLACE,
                },
                "msgtype": "m.text",
            },
            tok=self.mod_access_token,
        )
        edit_event_id = res["event_id"]

        # Also send a threaded message whose root is the same as the edit's.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message 1",
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.THREAD,
                },
            },
            tok=self.mod_access_token,
        )
        threaded_event_id = res["event_id"]

        # Also send a reaction, again with the same root.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Reaction,
            content={
                "m.relates_to": {
                    "rel_type": RelationTypes.ANNOTATION,
                    "event_id": root_event_id,
                    "key": "👍",
                }
            },
            tok=self.mod_access_token,
        )
        reaction_event_id = res["event_id"]

        # Redact the root event, specifying that we also want to delete all events that
        # relate to it.
        self._redact_event(
            self.mod_access_token,
            self.room_id,
            root_event_id,
            with_relations=["*"],
        )

        # Check that the root event got redacted.
        event_dict = self.helper.get_event(
            self.room_id, root_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the edit got redacted.
        event_dict = self.helper.get_event(
            self.room_id, edit_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the threaded message got redacted.
        event_dict = self.helper.get_event(
            self.room_id, threaded_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the reaction got redacted.
        event_dict = self.helper.get_event(
            self.room_id, reaction_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

    @override_config({"experimental_features": {"msc3912_enabled": True}})
    def test_redact_relations_no_perms(self) -> None:
        """Tests that, when redacting a message along with its relations, if not all
        the related messages can be redacted because of insufficient permissions, the
        server still redacts all the ones that can be.
        """
        # Send a root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "root",
            },
            tok=self.other_access_token,
        )
        root_event_id = res["event_id"]

        # Send a first threaded message, this one from the moderator. We do this for the
        # first message with the m.thread relation (and not the last one) to ensure
        # that, when the server fails to redact it, it doesn't stop there, and it
        # instead goes on to redact the other one.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message 1",
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.THREAD,
                },
            },
            tok=self.mod_access_token,
        )
        first_threaded_event_id = res["event_id"]

        # Send a second threaded message, this time from the user who'll perform the
        # redaction.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message 2",
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.THREAD,
                },
            },
            tok=self.other_access_token,
        )
        second_threaded_event_id = res["event_id"]

        # Redact the thread's root, and request that all threaded messages are also
        # redacted. Send that request from the non-mod user, so that the first threaded
        # event cannot be redacted.
        self._redact_event(
            self.other_access_token,
            self.room_id,
            root_event_id,
            with_relations=[RelationTypes.THREAD],
        )

        # Check that the thread root got redacted.
        event_dict = self.helper.get_event(
            self.room_id, root_event_id, self.other_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the last message in the thread got redacted, despite failing to
        # redact the one before it.
        event_dict = self.helper.get_event(
            self.room_id, second_threaded_event_id, self.other_access_token
        )
        self.assertIn("redacted_because", event_dict, event_dict)

        # Check that the message that was sent into the tread by the mod user is not
        # redacted.
        event_dict = self.helper.get_event(
            self.room_id, first_threaded_event_id, self.other_access_token
        )
        self.assertIn("body", event_dict["content"], event_dict)
        self.assertEqual("message 1", event_dict["content"]["body"])

    @override_config({"experimental_features": {"msc3912_enabled": True}})
    def test_redact_relations_txn_id_reuse(self) -> None:
        """Tests that redacting a message using a transaction ID, then reusing the same
        transaction ID but providing an additional list of relations to redact, is
        effectively a no-op.
        """
        # Send a root event.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "root",
            },
            tok=self.mod_access_token,
        )
        root_event_id = res["event_id"]

        # Send a first threaded message.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "I'm in a thread!",
                "m.relates_to": {
                    "event_id": root_event_id,
                    "rel_type": RelationTypes.THREAD,
                },
            },
            tok=self.mod_access_token,
        )
        threaded_event_id = res["event_id"]

        # Send a first redaction request which redacts only the root event.
        channel = self.make_request(
            method="PUT",
            path=f"/rooms/{self.room_id}/redact/{root_event_id}/foo",
            content={},
            access_token=self.mod_access_token,
        )
        self.assertEqual(channel.code, 200)

        # Send a second redaction request which redacts the root event as well as
        # threaded messages.
        channel = self.make_request(
            method="PUT",
            path=f"/rooms/{self.room_id}/redact/{root_event_id}/foo",
            content={"org.matrix.msc3912.with_relations": [RelationTypes.THREAD]},
            access_token=self.mod_access_token,
        )
        self.assertEqual(channel.code, 200)

        # Check that the root event got redacted.
        event_dict = self.helper.get_event(
            self.room_id, root_event_id, self.mod_access_token
        )
        self.assertIn("redacted_because", event_dict)

        # Check that the threaded message didn't get redacted (since that wasn't part of
        # the original redaction).
        event_dict = self.helper.get_event(
            self.room_id, threaded_event_id, self.mod_access_token
        )
        self.assertIn("body", event_dict["content"], event_dict)
        self.assertEqual("I'm in a thread!", event_dict["content"]["body"])

    @parameterized.expand(
        [
            # Tuples of:
            #   Room version
            #   Boolean: True if the redaction event content should include the event ID.
            #   Boolean: true if the resulting redaction event is expected to include the
            #            event ID in the content.
            (RoomVersions.V10, False, False),
            (RoomVersions.V11, True, True),
            (RoomVersions.V11, False, True),
        ]
    )
    def test_redaction_content(
        self, room_version: RoomVersion, include_content: bool, expect_content: bool
    ) -> None:
        """
        Room version 11 moved the redacts property to the content.

        Ensure that the event gets created properly and that the Client-Server
        API servers the proper backwards-compatible version.
        """
        # Create a room with the newer room version.
        room_id = self.helper.create_room_as(
            self.mod_user_id,
            tok=self.mod_access_token,
            room_version=room_version.identifier,
        )

        # Create an event.
        b = self.helper.send(room_id=room_id, tok=self.mod_access_token)
        event_id = b["event_id"]

        # Ensure the event ID in the URL and the content must match.
        if include_content:
            self._redact_event(
                self.mod_access_token,
                room_id,
                event_id,
                expect_code=400,
                content={"redacts": "foo"},
            )

        # Redact it for real.
        result = self._redact_event(
            self.mod_access_token,
            room_id,
            event_id,
            content={"redacts": event_id} if include_content else {},
        )
        redaction_event_id = result["event_id"]

        # Sync the room, to get the id of the create event
        timeline = self._sync_room_timeline(self.mod_access_token, room_id)
        redact_event = timeline[-1]
        self.assertEqual(redact_event["type"], EventTypes.Redaction)
        # The redacts key should be in the content and the redacts keys.
        self.assertEqual(redact_event["content"]["redacts"], event_id)
        self.assertEqual(redact_event["redacts"], event_id)

        # But it isn't actually part of the event.
        def get_event(txn: LoggingTransaction) -> JsonDict:
            return db_to_json(
                main_datastore._fetch_event_rows(txn, [redaction_event_id])[
                    redaction_event_id
                ].json
            )

        main_datastore = self.hs.get_datastores().main
        event_json = self.get_success(
            main_datastore.db_pool.runInteraction("get_event", get_event)
        )
        self.assertEqual(event_json["type"], EventTypes.Redaction)
        if expect_content:
            self.assertNotIn("redacts", event_json)
            self.assertEqual(event_json["content"]["redacts"], event_id)
        else:
            self.assertEqual(event_json["redacts"], event_id)
            self.assertNotIn("redacts", event_json["content"])


class MediaDeletionOnRedactionTests(HomeserverTestCase):
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
        with_relations: Optional[List[str]] = None,
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

    def _create_test_resource(self) -> Tuple[List, List]:
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

    def test_is_moderator(self) -> None:
        """Test BaseAuth function `is_moderator`"""
        # Admin is a moderator
        assert isinstance(self.auth, BaseAuth)
        admin = Requester(
            user=UserID.from_string(self.admin),
            access_token_id=None,
            is_guest=False,
            scope={"scope"},
            shadow_banned=False,
            device_id=None,
            app_service=None,
            authenticated_entity="auth",
        )
        assert self.get_success(self.auth.is_moderator(self.room, admin))

        # Normal user is not a moderator
        self.helper.join(self.room, self.user, tok=self.user_tok)
        user = Requester(
            user=UserID.from_string(self.user),
            access_token_id=None,
            is_guest=False,
            scope={"scope"},
            shadow_banned=False,
            device_id=None,
            app_service=None,
            authenticated_entity="auth",
        )
        assert not self.get_success(self.auth.is_moderator(self.room, user))

        # Update power level to make normal user a moderator
        power_levels = self.helper.get_state(
            self.room,
            "m.room.power_levels",
            tok=self.user_tok,
        )
        power_levels["users"][self.user] = 80
        self.helper.send_state(
            self.room,
            "m.room.power_levels",
            body=power_levels,
            tok=self.admin_tok,
        )
        assert self.get_success(self.auth.is_moderator(self.room, user))

    def test_get_media_ids_attached_to_event(self) -> None:
        """Test db function `get_media_ids_attached_to_event`"""
        # Create events with media attached
        media_ids, event_ids = self._create_test_resource()

        # Check if `get_media_ids_attached_to_event` can get media ids attached to an event
        for event_id in event_ids:
            media_ids = self.get_success(
                self.store.get_media_ids_attached_to_event(event_id)
            )
            assert len(media_ids) == 1

    def test_redacting_media_deletes_attached_media(self) -> None:
        """Test that the redacted media cleanup loop deletes media that has been
        redacted before 48 hours.
        """
        # Confirm that there are no redacted events at the start
        current_redacted_events = self.get_success(
            self.store.get_redacted_event_ids_before_interval(0)
        )
        assert len(current_redacted_events) == 0

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

        # Confirm that the redacted events are recorded in the db
        current_redacted_events = self.get_success(
            self.store.get_redacted_event_ids_before_interval(0)
        )
        # assert all(item in current_redacted_events for item in event_ids)
        assert event_ids == current_redacted_events

        # Fast forward 49 hours to make sure the redacted media cleanup loop runs
        self.reactor.advance(49 * 60 * 60)

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

        # Normal user trying to access redacted media should get 403
        for media_id in media_ids:
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}",
                shorthand=False,
                access_token=self.user_tok,
            )
            assert channel.code == 403

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
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}",
                shorthand=False,
                access_token=self.admin_tok,
            )
            assert channel.code == 200

        # After 48 hours, media that are attached to the redacted events should be
        # permanatly deleted from disk and moderators no longer have access to them
        self.reactor.advance(49 * 60 * 60)

        for media_id in media_ids:
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v1/media/download/{self.hs.hostname}/{media_id}",
                shorthand=False,
                access_token=self.admin_tok,
            )
            assert channel.code == 404
