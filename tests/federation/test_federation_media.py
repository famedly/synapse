#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
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
import json
import os
import shutil
import tempfile
from typing import Dict, Optional
from unittest.mock import AsyncMock, Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.media.filepath import MediaFilePaths
from synapse.media.media_storage import MediaStorage
from synapse.media.storage_provider import (
    FileStorageProviderBackend,
    StorageProviderWrapper,
)
from synapse.rest import admin
from synapse.rest.client import login, media
from synapse.server import HomeServer
from synapse.storage.database import LoggingTransaction
from synapse.storage.databases.main.media_repository import MediaRestrictions
from synapse.types import JsonDict, UserID
from synapse.util import Clock, json_encoder
from synapse.util.stringutils import random_string

from tests import unittest
from tests.media.test_media_storage import small_png
from tests.test_utils import SMALL_PNG


class FederationMediaDownloadsTest(unittest.FederatingHomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")
        self.addCleanup(shutil.rmtree, self.test_dir)
        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")

        hs.config.media.media_store_path = self.primary_base_path

        storage_providers = [
            StorageProviderWrapper(
                FileStorageProviderBackend(hs, self.secondary_base_path),
                store_local=True,
                store_remote=False,
                store_synchronous=True,
            )
        ]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )
        self.media_repo = hs.get_media_repository()

    def test_file_download(self) -> None:
        content = io.BytesIO(b"file_to_stream")
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "text/plain",
                "test_upload",
                content,
                46,
                UserID.from_string("@user_id:whatever.org"),
            )
        )
        # test with a text file
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.pump()
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        # extract boundary
        boundary = content_type[0].split("boundary=")[1]
        # split on boundary and check that json field and expected value exist
        stripped = channel.text_body.split("\r\n" + "--" + boundary)
        # TODO: the json object expected will change once MSC3911 is implemented, currently
        # {} is returned for all requests as a placeholder (per MSC3196)
        found_json = any(
            "\r\nContent-Type: application/json\r\n\r\n{}" in field
            for field in stripped
        )
        self.assertTrue(found_json)

        # check that the text file and expected value exist
        found_file = any(
            "\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename=test_upload\r\n\r\nfile_to_stream"
            in field
            for field in stripped
        )
        self.assertTrue(found_file)

        content = io.BytesIO(SMALL_PNG)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                content,
                67,
                UserID.from_string("@user_id:whatever.org"),
            )
        )
        # test with an image file
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.pump()
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        # extract boundary
        boundary = content_type[0].split("boundary=")[1]
        # split on boundary and check that json field and expected value exist
        body = channel.result.get("body")
        assert body is not None
        stripped_bytes = body.split(b"\r\n" + b"--" + boundary.encode("utf-8"))
        found_json = any(
            b"\r\nContent-Type: application/json\r\n\r\n{}" in field
            for field in stripped_bytes
        )
        self.assertTrue(found_json)

        # check that the png file exists and matches what was uploaded
        found_file = any(SMALL_PNG in field for field in stripped_bytes)
        self.assertTrue(found_file)

    def test_federation_etag(self) -> None:
        """Test that federation ETags work"""

        content = io.BytesIO(b"file_to_stream")
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "text/plain",
                "test_upload",
                content,
                46,
                UserID.from_string("@user_id:whatever.org"),
            )
        )

        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.pump()
        self.assertEqual(200, channel.code)

        # We expect exactly one ETag header.
        etags = channel.headers.getRawHeaders("ETag")
        self.assertIsNotNone(etags)
        assert etags is not None  # For mypy
        self.assertEqual(len(etags), 1)
        etag = etags[0]

        # Refetching with the etag should result in 304 and empty body.
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
            custom_headers=[("If-None-Match", etag)],
        )
        self.pump()
        self.assertEqual(channel.code, 304)
        self.assertEqual(channel.is_finished(), True)
        self.assertNotIn("body", channel.result)


class FederationRestrictedMediaDownloadsTest(unittest.FederatingHomeserverTestCase):
    """
    Test that answering a federation download media request behaves appropriately

    More specifically, test that:
    * downloads are achieved if restrictions are set
    * downloads are blocked if restrictions are not set
    * downloads are blocked if restrictions are malformed
    """

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")
        self.addCleanup(shutil.rmtree, self.test_dir)
        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")
        hs.config.media.media_store_path = self.primary_base_path
        self.store = hs.get_datastores().main

        storage_providers = [
            StorageProviderWrapper(
                FileStorageProviderBackend(hs, self.secondary_base_path),
                store_local=True,
                store_remote=False,
                store_synchronous=True,
            )
        ]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )
        self.media_repo = hs.get_media_repository()

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911_enabled": True})
        return config

    def test_restricted_media_download_with_restrictions_field(self) -> None:
        """
        Test that a federation download media request can succeed and is shaped as
        expected.
        """
        content = io.BytesIO(SMALL_PNG)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                content,
                67,
                UserID.from_string("@user_id:something.org"),
                restricted=True,
            )
        )
        # Attach restrictions to the media
        self.get_success(
            self.media_repo.store.set_media_restricted_to_event_id(
                self.hs.hostname, content_uri.media_id, "random-event-id"
            )
        )
        # Send download request with federation endpoint
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        boundary = content_type[0].split("boundary=")[1]
        body = channel.result.get("body")
        assert body is not None

        # Assert a JSON part exists with field restrictions
        stripped_bytes = body.split(b"\r\n" + b"--" + boundary.encode("utf-8"))
        json_obj = None
        for part in stripped_bytes:
            if b"Content-Type: application/json" in part:
                idx = part.find(b"\r\n\r\n")
                assert idx != -1, "No JSON payload found after header"
                json_bytes = part[idx + 4 :].strip()
                json_obj = json.loads(json_bytes.decode("utf-8"))
                break

        assert json_obj is not None, "No JSON part found"
        assert (
            json_obj.get("org.matrix.msc3911.restrictions", {}).get("event_id")
            == "random-event-id"
        )

        # Check the png file exists and matches what was uploaded
        found_file = any(SMALL_PNG in field for field in stripped_bytes)
        self.assertTrue(found_file)

    def test_restricted_media_download_without_restrictions_field_fails(self) -> None:
        """
        Test that restricted media with no restrictions defined is denied over federation
        """
        # More specifically, restricted is marked True in the database, but the
        # associated table of attachments has no entries. Do not confuse this with the
        # potential of restricted being True, but the restrictions being defined but
        # empty(as `{}`)
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

        # Send download request with federation endpoint
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.assertEqual(404, channel.code)
        self.assertIn(b"Not found", channel.result.get("body", b""))

    def test_restricted_media_download_with_invalid_restrictions_field_fails(
        self,
    ) -> None:
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
        # Append invalid restrictions set for test
        json_object = {"random_field": "random_value"}

        def insert_restriction(txn: LoggingTransaction) -> None:
            self.store.db_pool.simple_insert_txn(
                txn,
                table="media_attachments",
                values={
                    "server_name": self.hs.hostname,
                    "media_id": content_uri.media_id,
                    "restrictions_json": json_encoder.encode(json_object),
                },
            )

        self.get_success(
            self.store.db_pool.runInteraction(
                "test_restricted_media_download_with_invalid_restrictions_field_fails",
                insert_restriction,
            )
        )

        # Send download request with federation endpoint
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/download/{content_uri.media_id}",
        )
        self.assertEqual(403, channel.code)
        self.assertIn(
            b"MediaRestrictions must have exactly one of",
            channel.result.get("body", b""),
        )


class FederationThumbnailTest(unittest.FederatingHomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")
        self.addCleanup(shutil.rmtree, self.test_dir)
        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")

        hs.config.media.media_store_path = self.primary_base_path

        storage_providers = [
            StorageProviderWrapper(
                FileStorageProviderBackend(hs, self.secondary_base_path),
                store_local=True,
                store_remote=False,
                store_synchronous=True,
            )
        ]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )
        self.media_repo = hs.get_media_repository()

    def test_thumbnail_download_scaled(self) -> None:
        content = io.BytesIO(small_png.data)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_thumbnail",
                content,
                67,
                UserID.from_string("@user_id:whatever.org"),
            )
        )
        # test with an image file
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/thumbnail/{content_uri.media_id}?width=32&height=32&method=scale",
        )
        self.pump()
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        # extract boundary
        boundary = content_type[0].split("boundary=")[1]
        # split on boundary and check that json field and expected value exist
        body = channel.result.get("body")
        assert body is not None
        stripped_bytes = body.split(b"\r\n" + b"--" + boundary.encode("utf-8"))
        found_json = any(
            b"\r\nContent-Type: application/json\r\n\r\n{}" in field
            for field in stripped_bytes
        )
        self.assertTrue(found_json)

        # check that the png file exists and matches the expected scaled bytes
        found_file = any(small_png.expected_scaled in field for field in stripped_bytes)
        self.assertTrue(found_file)

    def test_thumbnail_download_cropped(self) -> None:
        content = io.BytesIO(small_png.data)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_thumbnail",
                content,
                67,
                UserID.from_string("@user_id:whatever.org"),
            )
        )
        # test with an image file
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/thumbnail/{content_uri.media_id}?width=32&height=32&method=crop",
        )
        self.pump()
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        # extract boundary
        boundary = content_type[0].split("boundary=")[1]
        # split on boundary and check that json field and expected value exist
        body = channel.result.get("body")
        assert body is not None
        stripped_bytes = body.split(b"\r\n" + b"--" + boundary.encode("utf-8"))
        found_json = any(
            b"\r\nContent-Type: application/json\r\n\r\n{}" in field
            for field in stripped_bytes
        )
        self.assertTrue(found_json)

        # check that the png file exists and matches the expected cropped bytes
        found_file = any(
            small_png.expected_cropped in field for field in stripped_bytes
        )
        self.assertTrue(found_file)


class FederationRestrictedThumbnailTest(unittest.FederatingHomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")
        self.addCleanup(shutil.rmtree, self.test_dir)
        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")

        hs.config.media.media_store_path = self.primary_base_path

        storage_providers = [
            StorageProviderWrapper(
                FileStorageProviderBackend(hs, self.secondary_base_path),
                store_local=True,
                store_remote=False,
                store_synchronous=True,
            )
        ]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )
        self.media_repo = hs.get_media_repository()

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911_enabled": True})
        return config

    def test_restricted_thumbnail_download_with_restrictions_field(self) -> None:
        content = io.BytesIO(small_png.data)
        content_uri = self.get_success(
            self.media_repo.create_or_update_content(
                "image/png",
                "test_png_thumbnail",
                content,
                67,
                UserID.from_string("@user_id:whatever.org"),
                restricted=True,
            )
        )
        # Attach restrictions to the media
        self.get_success(
            self.media_repo.store.set_media_restricted_to_user_profile(
                self.hs.hostname, content_uri.media_id, "@user_id:whatever.org"
            )
        )

        # Send download request with federation endpoint
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/media/thumbnail/{content_uri.media_id}?width=32&height=32&method=scale",
        )
        self.assertEqual(200, channel.code)

        content_type = channel.headers.getRawHeaders("content-type")
        assert content_type is not None
        assert "multipart/mixed" in content_type[0]
        assert "boundary" in content_type[0]

        boundary = content_type[0].split("boundary=")[1]
        body = channel.result.get("body")
        assert body is not None

        # Assert a JSON part exists with field restrictions
        stripped_bytes = body.split(b"\r\n" + b"--" + boundary.encode("utf-8"))
        json_obj = None
        for part in stripped_bytes:
            if b"Content-Type: application/json" in part:
                idx = part.find(b"\r\n\r\n")
                assert idx != -1, "No JSON payload found after header"
                json_bytes = part[idx + 4 :].strip()
                json_obj = json.loads(json_bytes.decode("utf-8"))
                break

        assert json_obj is not None, "No JSON part found"
        assert (
            json_obj.get("org.matrix.msc3911.restrictions", {}).get("profile_user_id")
            == "@user_id:whatever.org"
        )

        # Check that the png file exists and matches the expected scaled bytes
        found_file = any(small_png.expected_scaled in field for field in stripped_bytes)
        self.assertTrue(found_file)


class FederationClientDownloadTestCase(unittest.HomeserverTestCase):
    """
    Test that an outgoing remote request for federation media is correctly parsed and
    inserted into the local database
    """

    test_image = small_png
    headers = {
        b"Content-Length": [b"%d" % (len(test_image.data))],
        b"Content-Type": [test_image.content_type],
        b"Content-Disposition": [b"inline"],
    }

    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        # Mock out the homeserver's MatrixFederationHttpClient
        client = Mock()
        federation_get_file = AsyncMock()
        client.federation_get_file = federation_get_file
        self.fed_client_mock = federation_get_file

        hs = self.setup_test_homeserver(federation_http_client=client)

        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.media_repo = hs.get_media_repository()

        self.remote_server = "example.com"
        # mapping of media_id -> byte string of the json with the restrictions
        self.media_id_data: Dict[str, bytes] = {}

        self.user = self.register_user("user", "pass")
        self.tok = self.login("user", "pass")

    def generate_remote_media_id_and_restrictions(
        self, json_dict_response: Optional[JsonDict] = None
    ) -> str:
        """
        Create a mocked remote media to retrieve

        Args:
            json_dict_response: The attachments object that is included in the multipart
                response received from federation
        """
        media_id = random_string(24)
        byte_string = b"{}"
        if json_dict_response:
            byte_string = json_encoder.encode(json_dict_response).encode()

        self.media_id_data[media_id] = byte_string
        return media_id

    def make_request_for_media(
        self, json_dict_response: Optional[JsonDict] = None, expected_code: int = 200
    ) -> str:
        """
        Place a request to a (mocked) remote server. The request being placed is
        actually to the local server, but redirects to the remote to retrieve the media.
        This should insert the json part of the response automatically into the database
        for us
        """
        # Generate media id and restrictions based on SMALL_PNG
        media_id = self.generate_remote_media_id_and_restrictions(json_dict_response)
        self.fed_client_mock.return_value = (
            67,
            self.headers,
            self.media_id_data[media_id],
        )

        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.remote_server}/{media_id}",
            shorthand=False,
            access_token=self.tok,
        )

        self.assertEqual(channel.code, expected_code)

        return media_id

    def test_downloading_remote_media_with_restrictions_is_in_database(self) -> None:
        """
        Test that remote media with restrictions correctly is inserted to the database
        """
        # Note the unstable prefix is filtered out properly before persistence
        media_id = self.make_request_for_media(
            {"org.matrix.msc3911.restrictions": {"profile_user_id": "@bob:example.com"}}
        )
        restrictions = self.get_success(
            self.store.get_media_restrictions(self.remote_server, media_id)
        )
        assert isinstance(restrictions, MediaRestrictions)
        assert restrictions.profile_user_id is not None
        assert restrictions.profile_user_id == "@bob:example.com"

    def test_downloading_remote_media_with_no_restrictions_does_not_save_to_db(
        self,
    ) -> None:
        """Test that remote media with no restrictions correctly skips a database entry"""
        media_id = self.make_request_for_media()
        restrictions = self.get_success(
            self.store.get_media_restrictions(self.remote_server, media_id)
        )
        assert restrictions is None
