#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2014-2016 OpenMarket Ltd
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

"""Tests REST events for /profile paths."""

import io
import urllib.parse
from http import HTTPStatus
from typing import Any, Dict, Optional

from canonicaljson import encode_canonical_json
from matrix_common.types.mxc_uri import MXCUri

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.errors import Codes
from synapse.rest import admin
from synapse.rest.client import login, media, profile, room
from synapse.server import HomeServer
from synapse.storage.databases.main.profile import MAX_PROFILE_SIZE
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG
from tests.utils import USE_POSTGRES_FOR_TESTS


class ProfileTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.hs = self.setup_test_homeserver()
        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")
        self.other = self.register_user("other", "pass", displayname="Bob")

    def test_get_displayname(self) -> None:
        res = self._get_displayname()
        self.assertEqual(res, "owner")

    def test_get_displayname_rejects_bad_username(self) -> None:
        channel = self.make_request(
            "GET", f"/profile/{urllib.parse.quote('@alice:')}/displayname"
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)

    def test_set_displayname(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self._get_displayname()
        self.assertEqual(res, "test")

    def test_set_displayname_with_extra_spaces(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "  test  "},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self._get_displayname()
        self.assertEqual(res, "test")

    def test_set_displayname_noauth(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test"},
        )
        self.assertEqual(channel.code, 401, channel.result)

    def test_set_displayname_too_long(self) -> None:
        """Attempts to set a stupid displayname should get a 400"""
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test" * 100},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

        res = self._get_displayname()
        self.assertEqual(res, "owner")

    def test_get_displayname_other(self) -> None:
        res = self._get_displayname(self.other)
        self.assertEqual(res, "Bob")

    def test_set_displayname_other(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.other,),
            content={"displayname": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

    def test_get_avatar_url(self) -> None:
        res = self._get_avatar_url()
        self.assertIsNone(res)

    def test_set_avatar_url(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self._get_avatar_url()
        self.assertEqual(res, "http://my.server/pic.gif")

    def test_set_avatar_url_noauth(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif"},
        )
        self.assertEqual(channel.code, 401, channel.result)

    def test_set_avatar_url_too_long(self) -> None:
        """Attempts to set a stupid avatar_url should get a 400"""
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif" * 100},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

        res = self._get_avatar_url()
        self.assertIsNone(res)

    def test_get_avatar_url_other(self) -> None:
        res = self._get_avatar_url(self.other)
        self.assertIsNone(res)

    def test_set_avatar_url_other(self) -> None:
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.other,),
            content={"avatar_url": "http://my.server/pic.gif"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

    def _get_displayname(self, name: Optional[str] = None) -> Optional[str]:
        channel = self.make_request(
            "GET", "/profile/%s/displayname" % (name or self.owner,)
        )
        self.assertEqual(channel.code, 200, channel.result)
        # FIXME: If a user has no displayname set, Synapse returns 200 and omits a
        # displayname from the response. This contradicts the spec, see
        # https://github.com/matrix-org/synapse/issues/13137.
        return channel.json_body.get("displayname")

    def _get_avatar_url(self, name: Optional[str] = None) -> Optional[str]:
        channel = self.make_request(
            "GET", "/profile/%s/avatar_url" % (name or self.owner,)
        )
        self.assertEqual(channel.code, 200, channel.result)
        # FIXME: If a user has no avatar set, Synapse returns 200 and omits an
        # avatar_url from the response. This contradicts the spec, see
        # https://github.com/matrix-org/synapse/issues/13137.
        return channel.json_body.get("avatar_url")

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_size_limit_global(self) -> None:
        """Tests that the maximum size limit for avatars is enforced when updating a
        global profile.
        """
        self._setup_local_files(
            {
                "small": {"size": 40},
                "big": {"size": 60},
            }
        )

        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://test/big"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 403, channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.FORBIDDEN, channel.json_body
        )

        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://test/small"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_size_limit_per_room(self) -> None:
        """Tests that the maximum size limit for avatars is enforced when updating a
        per-room profile.
        """
        self._setup_local_files(
            {
                "small": {"size": 40},
                "big": {"size": 60},
            }
        )

        room_id = self.helper.create_room_as(tok=self.owner_tok)

        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/state/m.room.member/{self.owner}",
            content={"membership": "join", "avatar_url": "mxc://test/big"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 403, channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.FORBIDDEN, channel.json_body
        )

        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/state/m.room.member/{self.owner}",
            content={"membership": "join", "avatar_url": "mxc://test/small"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    @unittest.override_config({"allowed_avatar_mimetypes": ["image/png"]})
    def test_avatar_allowed_mime_type_global(self) -> None:
        """Tests that the MIME type whitelist for avatars is enforced when updating a
        global profile.
        """
        self._setup_local_files(
            {
                "good": {"mimetype": "image/png"},
                "bad": {"mimetype": "application/octet-stream"},
            }
        )

        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://test/bad"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 403, channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.FORBIDDEN, channel.json_body
        )

        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://test/good"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    @unittest.override_config({"allowed_avatar_mimetypes": ["image/png"]})
    def test_avatar_allowed_mime_type_per_room(self) -> None:
        """Tests that the MIME type whitelist for avatars is enforced when updating a
        per-room profile.
        """
        self._setup_local_files(
            {
                "good": {"mimetype": "image/png"},
                "bad": {"mimetype": "application/octet-stream"},
            }
        )

        room_id = self.helper.create_room_as(tok=self.owner_tok)

        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/state/m.room.member/{self.owner}",
            content={"membership": "join", "avatar_url": "mxc://test/bad"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 403, channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.FORBIDDEN, channel.json_body
        )

        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/state/m.room.member/{self.owner}",
            content={"membership": "join", "avatar_url": "mxc://test/good"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    @unittest.override_config(
        {"experimental_features": {"msc4069_profile_inhibit_propagation": True}}
    )
    def test_msc4069_inhibit_propagation(self) -> None:
        """Tests to ensure profile update propagation can be inhibited."""
        for prop in ["avatar_url", "displayname"]:
            room_id = self.helper.create_room_as(tok=self.owner_tok)

            channel = self.make_request(
                "PUT",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                content={"membership": "join", prop: "mxc://my.server/existing"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            channel = self.make_request(
                "PUT",
                f"/profile/{self.owner}/{prop}?org.matrix.msc4069.propagate=false",
                content={prop: "http://my.server/pic.gif"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            res = (
                self._get_avatar_url()
                if prop == "avatar_url"
                else self._get_displayname()
            )
            self.assertEqual(res, "http://my.server/pic.gif")

            channel = self.make_request(
                "GET",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)
            self.assertEqual(channel.json_body.get(prop), "mxc://my.server/existing")

    def test_msc4069_inhibit_propagation_disabled(self) -> None:
        """Tests to ensure profile update propagation inhibit flags are ignored when the
        experimental flag is not enabled.
        """
        for prop in ["avatar_url", "displayname"]:
            room_id = self.helper.create_room_as(tok=self.owner_tok)

            channel = self.make_request(
                "PUT",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                content={"membership": "join", prop: "mxc://my.server/existing"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            channel = self.make_request(
                "PUT",
                f"/profile/{self.owner}/{prop}?org.matrix.msc4069.propagate=false",
                content={prop: "http://my.server/pic.gif"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            res = (
                self._get_avatar_url()
                if prop == "avatar_url"
                else self._get_displayname()
            )
            self.assertEqual(res, "http://my.server/pic.gif")

            channel = self.make_request(
                "GET",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            # The ?propagate=false should be ignored by the server because the config flag
            # isn't enabled.
            self.assertEqual(channel.json_body.get(prop), "http://my.server/pic.gif")

    def test_msc4069_inhibit_propagation_default(self) -> None:
        """Tests to ensure profile update propagation happens by default."""
        for prop in ["avatar_url", "displayname"]:
            room_id = self.helper.create_room_as(tok=self.owner_tok)

            channel = self.make_request(
                "PUT",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                content={"membership": "join", prop: "mxc://my.server/existing"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            channel = self.make_request(
                "PUT",
                f"/profile/{self.owner}/{prop}",
                content={prop: "http://my.server/pic.gif"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            res = (
                self._get_avatar_url()
                if prop == "avatar_url"
                else self._get_displayname()
            )
            self.assertEqual(res, "http://my.server/pic.gif")

            channel = self.make_request(
                "GET",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            # The ?propagate=false should be ignored by the server because the config flag
            # isn't enabled.
            self.assertEqual(channel.json_body.get(prop), "http://my.server/pic.gif")

    @unittest.override_config(
        {"experimental_features": {"msc4069_profile_inhibit_propagation": True}}
    )
    def test_msc4069_inhibit_propagation_like_default(self) -> None:
        """Tests to ensure clients can request explicit profile propagation."""
        for prop in ["avatar_url", "displayname"]:
            room_id = self.helper.create_room_as(tok=self.owner_tok)

            channel = self.make_request(
                "PUT",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                content={"membership": "join", prop: "mxc://my.server/existing"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            channel = self.make_request(
                "PUT",
                f"/profile/{self.owner}/{prop}?org.matrix.msc4069.propagate=true",
                content={prop: "http://my.server/pic.gif"},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            res = (
                self._get_avatar_url()
                if prop == "avatar_url"
                else self._get_displayname()
            )
            self.assertEqual(res, "http://my.server/pic.gif")

            channel = self.make_request(
                "GET",
                f"/rooms/{room_id}/state/m.room.member/{self.owner}",
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

            # The client requested ?propagate=true, so it should have happened.
            self.assertEqual(channel.json_body.get(prop), "http://my.server/pic.gif")

    def test_get_missing_custom_field(self) -> None:
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
        )
        self.assertEqual(channel.code, HTTPStatus.NOT_FOUND, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_get_missing_custom_field_invalid_field_name(self) -> None:
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}/[custom_field]",
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

    def test_get_custom_field_rejects_bad_username(self) -> None:
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{urllib.parse.quote('@alice:')}/custom_field",
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

    def test_set_custom_field(self) -> None:
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
            content={"custom_field": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEqual(channel.json_body, {"custom_field": "test"})

        # Overwriting the field should work.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
            content={"custom_field": "new_Value"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEqual(channel.json_body, {"custom_field": "new_Value"})

        # Deleting the field should work.
        channel = self.make_request(
            "DELETE",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
            content={},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
        )
        self.assertEqual(channel.code, HTTPStatus.NOT_FOUND, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_non_string(self) -> None:
        """Non-string fields are supported for custom fields."""
        fields = {
            "bool_field": True,
            "array_field": ["test"],
            "object_field": {"test": "test"},
            "numeric_field": 1,
            "null_field": None,
        }

        for key, value in fields.items():
            channel = self.make_request(
                "PUT",
                f"/_matrix/client/v3/profile/{self.owner}/{key}",
                content={key: value},
                access_token=self.owner_tok,
            )
            self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}",
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEqual(channel.json_body, {"displayname": "owner", **fields})

        # Check getting individual fields works.
        for key, value in fields.items():
            channel = self.make_request(
                "GET",
                f"/_matrix/client/v3/profile/{self.owner}/{key}",
            )
            self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
            self.assertEqual(channel.json_body, {key: value})

    def test_set_custom_field_noauth(self) -> None:
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
            content={"custom_field": "test"},
        )
        self.assertEqual(channel.code, 401, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.MISSING_TOKEN)

    def test_set_custom_field_size(self) -> None:
        """
        Attempts to set a custom field name that is too long should get a 400 error.
        """
        # Key is missing.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/",
            content={"": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

        # Single key is too large.
        key = "c" * 500
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.KEY_TOO_LARGE)

        channel = self.make_request(
            "DELETE",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.KEY_TOO_LARGE)

        # Key doesn't match body.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/custom_field",
            content={"diff_key": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.MISSING_PARAM)

    def test_set_custom_field_profile_too_long(self) -> None:
        """
        Attempts to set a custom field that would push the overall profile too large.
        """
        # Get right to the boundary:
        #   len("displayname") + len("owner") + 5 = 21 for the displayname
        #   1 + 65498 + 5 for key "a" = 65504
        #   2 braces, 1 comma
        # 3 + 21 + 65498 = 65522 < 65536.
        key = "a"
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: "a" * 65498},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        # Get the entire profile.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v3/profile/{self.owner}",
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)
        canonical_json = encode_canonical_json(channel.json_body)
        # 6 is the minimum bytes to store a value: 4 quotes, 1 colon, 1 comma, an empty key.
        # Be one below that so we can prove we're at the boundary.
        self.assertEqual(len(canonical_json), MAX_PROFILE_SIZE - 8)

        # Postgres stores JSONB with whitespace, while SQLite doesn't.
        if USE_POSTGRES_FOR_TESTS:
            ADDITIONAL_CHARS = 0
        else:
            ADDITIONAL_CHARS = 1

        # The next one should fail, note the value has a (JSON) length of 2.
        key = "b"
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: "1" + "a" * ADDITIONAL_CHARS},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.PROFILE_TOO_LARGE)

        # Setting an avatar or (longer) display name should not work.
        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/displayname",
            content={"displayname": "owner12345678" + "a" * ADDITIONAL_CHARS},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.PROFILE_TOO_LARGE)

        channel = self.make_request(
            "PUT",
            f"/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://foo/bar"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.PROFILE_TOO_LARGE)

        # Removing a single byte should work.
        key = "b"
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: "" + "a" * ADDITIONAL_CHARS},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        # Finally, setting a field that already exists to a value that is <= in length should work.
        key = "a"
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/{key}",
            content={key: ""},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    def test_set_custom_field_displayname(self) -> None:
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/displayname",
            content={"displayname": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        displayname = self._get_displayname()
        self.assertEqual(displayname, "test")

    def test_set_custom_field_avatar_url(self) -> None:
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.owner}/avatar_url",
            content={"avatar_url": "mxc://test/good"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        avatar_url = self._get_avatar_url()
        self.assertEqual(avatar_url, "mxc://test/good")

    def test_set_custom_field_other(self) -> None:
        """Setting someone else's profile field should fail"""
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.other}/custom_field",
            content={"custom_field": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 403, channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.FORBIDDEN)

    def _setup_local_files(self, names_and_props: Dict[str, Dict[str, Any]]) -> None:
        """Stores metadata about files in the database.

        Args:
            names_and_props: A dictionary with one entry per file, with the key being the
                file's name, and the value being a dictionary of properties. Supported
                properties are "mimetype" (for the file's type) and "size" (for the
                file's size).
        """
        store = self.hs.get_datastores().main

        for name, props in names_and_props.items():
            self.get_success(
                store.store_local_media(
                    media_id=name,
                    media_type=props.get("mimetype", "image/png"),
                    time_now_ms=self.clock.time_msec(),
                    upload_name=None,
                    media_length=props.get("size", 50),
                    user_id=UserID.from_string("@rin:test"),
                )
            )


class ProfilesRestrictedTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["require_auth_for_profile_requests"] = True
        config["limit_profile_requests_to_users_who_share_rooms"] = True
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # User owning the requested profile.
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")
        self.profile_url = "/profile/%s" % (self.owner)

        # User requesting the profile.
        self.requester = self.register_user("requester", "pass")
        self.requester_tok = self.login("requester", "pass")

        self.room_id = self.helper.create_room_as(self.owner, tok=self.owner_tok)

    def test_no_auth(self) -> None:
        self.try_fetch_profile(401)

    def test_not_in_shared_room(self) -> None:
        self.ensure_requester_left_room()

        self.try_fetch_profile(403, access_token=self.requester_tok)

    def test_in_shared_room(self) -> None:
        self.ensure_requester_left_room()

        self.helper.join(room=self.room_id, user=self.requester, tok=self.requester_tok)

        self.try_fetch_profile(200, self.requester_tok)

    def try_fetch_profile(
        self, expected_code: int, access_token: Optional[str] = None
    ) -> None:
        self.request_profile(expected_code, access_token=access_token)

        self.request_profile(
            expected_code, url_suffix="/displayname", access_token=access_token
        )

        self.request_profile(
            expected_code, url_suffix="/avatar_url", access_token=access_token
        )

    def request_profile(
        self,
        expected_code: int,
        url_suffix: str = "",
        access_token: Optional[str] = None,
    ) -> None:
        channel = self.make_request(
            "GET", self.profile_url + url_suffix, access_token=access_token
        )
        self.assertEqual(channel.code, expected_code, channel.result)

    def ensure_requester_left_room(self) -> None:
        try:
            self.helper.leave(
                room=self.room_id, user=self.requester, tok=self.requester_tok
            )
        except AssertionError:
            # We don't care whether the leave request didn't return a 200 (e.g.
            # if the user isn't already in the room), because we only want to
            # make sure the user isn't in the room.
            pass


class OwnProfileUnrestrictedTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["require_auth_for_profile_requests"] = True
        config["limit_profile_requests_to_users_who_share_rooms"] = True
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # User requesting the profile.
        self.requester = self.register_user("requester", "pass")
        self.requester_tok = self.login("requester", "pass")

    def test_can_lookup_own_profile(self) -> None:
        """Tests that a user can lookup their own profile without having to be in a room
        if 'require_auth_for_profile_requests' is set to true in the server's config.
        """
        channel = self.make_request(
            "GET", "/profile/" + self.requester, access_token=self.requester_tok
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            "/profile/" + self.requester + "/displayname",
            access_token=self.requester_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            "/profile/" + self.requester + "/avatar_url",
            access_token=self.requester_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)


class ProfileMediaAttachmentTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        media.register_servlets,
        profile.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.server_name = self.hs.config.server.server_name
        self.media_repo = self.hs.get_media_repository()

        self.user = self.register_user("user", "password")
        self.tok = self.login("user", "password")

        self.other_user = self.register_user("other_user", "password")
        self.other_tok = self.login("other_user", "password")

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911_enabled": True})
        return config

    def create_resource_dict(self) -> dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def create_media_and_set_restricted_flag(self, user_id: str) -> MXCUri:
        """
        Create media without using an endpoint, and set the restricted flag.
        """
        content = io.BytesIO(SMALL_PNG)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                content,
                67,
                UserID.from_string(user_id),
                restricted=True,
            )
        )
        return content_uri

    def test_can_attach_media_to_profile_update(self) -> None:
        """
        Test basic functionality, that a media ID can be attached to a user profile id.
        """
        mxc_uri = self.create_media_and_set_restricted_flag(self.user)
        # Update user profile with attach_media.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(mxc_uri)},
        )
        assert channel.code == HTTPStatus.OK
        assert channel.json_body == {}

        # Check if the media's restrictions field is updated with the profile_user_id.
        restrictions = self.get_success(
            self.store.get_media_restrictions(mxc_uri.server_name, mxc_uri.media_id)
        )
        assert restrictions is not None, str(restrictions)
        assert restrictions.event_id is None
        assert restrictions.profile_user_id == UserID.from_string(self.user)

    def test_attaching_nonexistent_media_to_profile_fails(self) -> None:
        """
        Test that media that does not exist is not allowed to be attached to a user profile.
        """
        # Generate non-existing media.
        nonexistent_mxc_uri = MXCUri.from_str("mxc://test/fakeMediaId")
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(nonexistent_mxc_uri)},
        )

        assert channel.code == HTTPStatus.BAD_REQUEST, channel.json_body
        assert channel.json_body["errcode"] == Codes.INVALID_PARAM
        assert "does not exist" in channel.json_body["error"]

    def test_attaching_unrestricted_media_to_profile_fails(self) -> None:
        """
        Test that attaching unrestricted media to user profile fails.
        """
        # Create unrestricted media.
        channel = self.make_request(
            "POST",
            "/_matrix/media/v3/upload?filename=test_png_upload",
            SMALL_PNG,
            access_token=self.tok,
            content_type=b"image/png",
            custom_headers=[("Content-Length", str(67))],
        )
        assert channel.code == 200, channel.result
        content_uri = MXCUri.from_str(channel.json_body["content_uri"])

        # Check media is unrestricted.
        media_info = self.get_success(self.store.get_local_media(content_uri.media_id))
        assert media_info is not None
        assert not media_info.restricted

        # Try to update user profile with unrestricted media.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(content_uri)},
        )
        assert channel.code == HTTPStatus.BAD_REQUEST, channel.json_body
        assert channel.json_body["errcode"] == Codes.INVALID_PARAM
        assert "is not restricted" in channel.json_body["error"]

    def test_attaching_already_attached_media_to_profile_fails(self) -> None:
        """
        Test that attaching already attached media to user profile fails.
        """
        mxc_uri = self.create_media_and_set_restricted_flag(self.user)
        # Attach the media to the user profile.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(mxc_uri)},
        )
        assert channel.code == HTTPStatus.OK
        assert channel.json_body == {}

        # Try attaching the same media again.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(mxc_uri)},
        )
        assert channel.code == HTTPStatus.BAD_REQUEST, channel.json_body
        assert channel.json_body["errcode"] == Codes.INVALID_PARAM
        assert "already has restrictions set" in channel.json_body["error"]

    def test_attaching_not_owned_media_to_profile_fails(self) -> None:
        """
        Test that attaching media not owned by the user to profile fails.
        """
        # Media is created with other_user.
        mxc_uri = self.create_media_and_set_restricted_flag(self.other_user)
        # Try to attach the media from other_user to user.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(mxc_uri)},
        )
        assert channel.code == HTTPStatus.BAD_REQUEST, channel.json_body
        assert channel.json_body["errcode"] == Codes.INVALID_PARAM
        assert "does not exist" in channel.json_body["error"]

    def test_remove_media_from_profile(self) -> None:
        """
        Test that removing media from user profile works.
        """
        mxc_uri = self.create_media_and_set_restricted_flag(self.user)
        # Attach the media to the user profile.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": str(mxc_uri)},
        )
        assert channel.code == HTTPStatus.OK
        assert channel.json_body == {}

        # Check media is set as user avatar.
        user_avatar = self.get_success(
            self.store.get_profile_avatar_url(
                UserID.from_string(self.user),
            )
        )
        assert user_avatar is not None
        assert "mxc://test/" + user_avatar == str(mxc_uri)

        # Remove the media from the user profile.
        channel = self.make_request(
            "PUT",
            f"/_matrix/client/v3/profile/{self.user}/avatar_url",
            access_token=self.tok,
            content={"avatar_url": ""},
        )
        assert channel.code == HTTPStatus.OK
        assert channel.json_body == {}

        # Check media is no longer attached.
        user_avatar = self.get_success(
            self.store.get_profile_avatar_url(
                UserID.from_string(self.user),
            )
        )
        assert user_avatar is None
