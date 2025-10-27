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
from typing import (
    BinaryIO,
    Dict,
    List,
    Tuple,
)
from unittest.mock import AsyncMock

from twisted.test.proto_helpers import MemoryReactor

from synapse.handlers.room_member import Ratelimiter
from synapse.media.filepath import MediaFilePaths
from synapse.media.media_repository import MediaRepository
from synapse.media.media_storage import FileResponder, MediaStorage
from synapse.media.storage_provider import (
    FileStorageProviderBackend,
    StorageProviderWrapper,
)
from synapse.rest.client import login
from synapse.server import HomeServer
from synapse.storage.database import LoggingTransaction
from synapse.types import JsonDict, UserID
from synapse.util import Clock, json_encoder
from synapse.util.stringutils import random_string

from tests import unittest
from tests.media.test_media_storage import small_png
from tests.test_utils import SMALL_PNG, SMALL_PNG_SHA256
from tests.unittest import override_config


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

    @override_config({"use_sha256_paths": True})
    def test_federation_download_remote_file_with_sha256_path(self) -> None:
        """Test `_get_remote_media_impl` function with federation endpoint can download remote media in sha256 path."""

        # Mock the federation download media function of the client.
        async def _mock_federation_download_media(
            destination: str,
            media_id: str,
            output_stream: BinaryIO,
            max_size: int,
            max_timeout_ms: int,
            download_ratelimiter: Ratelimiter,
            ip_address: str,
        ) -> Tuple[int, Dict[bytes, List[bytes]]]:
            output_stream.write(SMALL_PNG)
            output_stream.flush()
            headers = {
                b"Content-Type": [b"image/png"],
                b"Content-Disposition": [b"attachment; filename=test.png"],
                b"Content-Length": [b"67"],
            }
            return 67, headers

        self.media_repo.client.federation_download_media = (  # type: ignore
            _mock_federation_download_media
        )

        # Download remote media using `_get_remote_media_impl`
        server_name = "other_server.com"
        media_id = random_string(24)  # media id from the remote server
        max_timeout_ms = 1000
        ratelimiter = AsyncMock()
        ip_address = "127.0.0.1"
        assert isinstance(self.media_repo, MediaRepository)
        responder, media_info = self.get_success(
            self.media_repo._get_remote_media_impl(
                server_name=server_name,
                media_id=media_id,
                max_timeout_ms=max_timeout_ms,
                download_ratelimiter=ratelimiter,
                ip_address=ip_address,
                use_federation_endpoint=True,
                allow_authenticated=True,
            )
        )
        assert isinstance(responder, FileResponder)
        responder.open_file.seek(0)
        content = responder.open_file.read()
        assert content == SMALL_PNG
        assert media_info.media_id == media_id
        assert media_info.media_origin == server_name
        assert media_info.upload_name == "test.png"
        assert media_info.sha256 == SMALL_PNG_SHA256

        # Check if the file is saved in the media  table
        remote_media = self.get_success(
            self.media_repo.store.get_cached_remote_media(server_name, media_id)
        )
        assert remote_media is not None

        # Check if the file is saved in the filesystem with sha256 path
        assert os.path.exists(self.media_repo.filepaths.filepath_sha(SMALL_PNG_SHA256))

        # Check if the thumbnails are generated in the sha256 path
        assert os.path.exists(
            self.media_repo.filepaths.thumbnail_sha_dir(SMALL_PNG_SHA256)
        )
        thumbnail = self.get_success(
            self.media_repo.store.get_remote_media_thumbnail(
                server_name, media_id, 1, 1, "image/png"
            )
        )
        assert thumbnail is not None


class FederationRestrictedMediaDownloadsTest(unittest.FederatingHomeserverTestCase):
    servlets = [
        login.register_servlets,
    ]

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
