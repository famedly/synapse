import io
import os
import shutil
import typing
from typing import (
    BinaryIO,
    Dict,
    List,
    Tuple,
)
from unittest.mock import AsyncMock

from matrix_common.types.mxc_uri import MXCUri

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media._base import FileInfo
from synapse.media.media_repository import MediaRepository
from synapse.media.media_storage import FileResponder
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import SMALL_PNG, SMALL_PNG_SHA256, SMALL_PNG_SHA256_PATH

if typing.TYPE_CHECKING:
    # conditional imports to avoid import cycle
    from synapse.handlers.room_member import Ratelimiter


class MediaRepositorySha256PathTestCase(unittest.HomeserverTestCase):
    hijack_auth = True
    servlets = [
        media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    def safe_cleanup_media(self) -> None:
        media_path = os.path.abspath("media")
        if os.path.exists(media_path):
            shutil.rmtree(media_path, ignore_errors=True)

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config.setdefault("experimental_features", {})
        config["experimental_features"].update({"msc3911_enabled": True})
        config["use_sha256_paths"] = True

        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.safe_cleanup_media()  # clean up the media directory if it exists
        # self.test_dir = tempfile.mkdtemp(prefix="media")
        # self.test_dir = "media/"
        self.addCleanup(self.safe_cleanup_media)
        # self.primary_base_path = os.path.join(self.test_dir, "primary")
        # self.secondary_base_path = os.path.join(self.test_dir, "secondary")
        # storage_providers = [FileStorageProviderBackend(hs, self.secondary_base_path)]
        # self.media_storage = MediaStorage(
        #     hs, self.primary_base_path, self.filepaths, storage_providers
        # )
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

    def _store_media_with_path(self, file_info: FileInfo, expected_path: str) -> None:
        assert isinstance(self.repo, MediaRepository)
        ctx = self.repo.media_storage.store_into_file(file_info)
        (f, fname) = self.get_success(ctx.__aenter__())
        f.write(SMALL_PNG)
        self.get_success(ctx.__aexit__(None, None, None))

        assert expected_path in fname
        assert os.path.exists(fname), f"File does not exist: {fname}"

    def _create_media_with_sha256_path(self, user: str) -> MXCUri:
        # Confirm that the sha256 path does not exist
        expected_path = os.path.join("media", SMALL_PNG_SHA256_PATH)
        mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                media_type="image/png",
                upload_name="test_png_upload",
                content=io.BytesIO(SMALL_PNG),
                content_length=67,
                auth_user=UserID.from_string(user),
                media_id=None,
                restricted=True,
            )
        )
        # Assert that if the media is created with sha256path
        assert os.path.exists(expected_path), f"File does not exist: {expected_path}"
        return mxc_uri

    def _create_media_with_original_path(self, user: str) -> MXCUri:
        assert isinstance(self.repo, MediaRepository)
        self.repo.use_sha256_paths = False
        mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                media_type="image/png",
                upload_name="original_media",
                content=io.BytesIO(SMALL_PNG),
                content_length=67,
                auth_user=UserID.from_string(user),
                media_id=None,
                restricted=True,
            )
        )
        # Assert that if the media is created with sha256path
        media_id = mxc_uri.media_id

        file_info = FileInfo(
            server_name=None,
            file_id=media_id,
        )
        assert isinstance(self.repo, MediaRepository)
        expected_path = self.repo.filepaths.local_media_filepath(media_id)
        self._store_media_with_path(file_info, expected_path)
        assert os.path.exists(expected_path), f"File does not exist: {expected_path}"
        self.repo.use_sha256_paths = True
        return mxc_uri

    def _create_remote_media_with_media_id_path(self, server_name: str) -> str:
        media_id = random_string(24)
        upload_name = "other_server_media"
        file_info = FileInfo(
            server_name=server_name,
            file_id=media_id,
        )
        assert isinstance(self.repo, MediaRepository)
        expected_path = self.repo.filepaths.remote_media_filepath(server_name, media_id)
        self._store_media_with_path(file_info, expected_path)
        assert os.path.exists(expected_path), f"File does not exist: {expected_path}"

        self.get_success(
            self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type="image/png",
                media_length=67,
                time_now_ms=self.clock.time_msec(),
                upload_name=upload_name,
                filesystem_id=media_id,
                sha256=SMALL_PNG_SHA256,
                restricted=True,
            )
        )

        remote_media = self.get_success(
            self.repo.store.get_cached_remote_media(server_name, media_id)
        )
        assert remote_media is not None
        assert remote_media.upload_name == upload_name
        assert remote_media.sha256 == SMALL_PNG_SHA256

        return media_id

    def _create_remote_media_with_sha256_path(self, server_name: str) -> str:
        media_id = random_string(24)
        upload_name = "other_server_media"
        file_info = FileInfo(
            server_name=server_name,
            file_id=media_id,
            sha256=SMALL_PNG_SHA256,
        )
        assert isinstance(self.repo, MediaRepository)
        expected_path = self.repo.filepaths.filepath_sha(SMALL_PNG_SHA256)
        self._store_media_with_path(file_info, expected_path)
        assert os.path.exists(expected_path), f"File does not exist: {expected_path}"

        self.get_success(
            self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type="image/png",
                media_length=67,
                time_now_ms=self.clock.time_msec(),
                upload_name=upload_name,
                filesystem_id=SMALL_PNG_SHA256,
                sha256=SMALL_PNG_SHA256,
                restricted=True,
            )
        )

        remote_media = self.get_success(
            self.repo.store.get_cached_remote_media(server_name, media_id)
        )
        assert remote_media is not None
        assert remote_media.upload_name == upload_name
        assert remote_media.sha256 == SMALL_PNG_SHA256

        return media_id

    def test_check_file_path_exists_by_sha256(self) -> None:
        """Test that unrestricted media is not affected"""
        # `check_file_path_exists_by_sha256` returns False if the sha256 path does not exist
        assert isinstance(self.repo, MediaRepository)
        assert not self.repo.check_file_path_exists_by_sha256("invalid_sha256")

        # Create a file with the sha256 path
        file_info = FileInfo(
            server_name=None,
            file_id=random_string(24),
            sha256=SMALL_PNG_SHA256,
        )
        expected_path = os.path.join("media", SMALL_PNG_SHA256_PATH)
        self._store_media_with_path(file_info, expected_path)
        assert self.repo.check_file_path_exists_by_sha256(SMALL_PNG_SHA256)

    def test_create_or_update_content_creates_new_content_with_sha256_path(
        self,
    ) -> None:
        """Test that `create_or_update_content` function creates new media with sha256 path"""
        # Confirm that the sha256 path does not exist
        expected_path = os.path.join("media", SMALL_PNG_SHA256_PATH)
        assert not os.path.exists(expected_path)
        # Create a new media with sha256 path
        mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                media_type="image/png",
                upload_name="test_png_upload",
                content=io.BytesIO(SMALL_PNG),
                content_length=67,
                auth_user=UserID.from_string(self.creator),
                media_id=None,
                restricted=True,
            )
        )
        assert os.path.exists(expected_path)
        # Make sure the media is created with sha256 path and not using the old path
        assert isinstance(self.repo, MediaRepository)
        old_path = self.repo.filepaths.local_media_filepath(mxc_uri.media_id)
        assert not os.path.exists(old_path)

    def test_create_or_update_content_updates_content_with_original_path(self) -> None:
        """Test that `create_or_update_content` function can update existing media with media_id path"""
        # Create media with original path
        mxc_uri = self._create_media_with_original_path(self.creator)
        media_id = mxc_uri.media_id
        assert isinstance(self.repo, MediaRepository)

        # Update the media with the original path
        updated_mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                media_type="image/png",
                upload_name="new_upload_name",
                content=io.BytesIO(SMALL_PNG),
                content_length=67,
                auth_user=UserID.from_string(self.creator),
                media_id=media_id,
                restricted=True,
            )
        )
        assert mxc_uri.media_id == updated_mxc_uri.media_id
        assert os.path.exists(os.path.join("media", SMALL_PNG_SHA256_PATH))
        assert not os.path.exists(self.repo.filepaths.local_media_filepath(media_id))

    def test_create_or_update_content_updates_content_with_sha256_path(self) -> None:
        """Test that `create_or_update_content` function can update existing media with sha256 path"""
        # Create media with sha256 path
        mxc_uri = self._create_media_with_sha256_path(self.creator)
        media_id = mxc_uri.media_id
        # Update the media with the sha256 path
        updated_mxc_uri = self.get_success(
            self.repo.create_or_update_content(
                media_type="image/png",
                upload_name="new_upload_name",
                content=io.BytesIO(SMALL_PNG),
                content_length=67,
                auth_user=UserID.from_string(self.creator),
                media_id=media_id,
                restricted=True,
            )
        )
        assert mxc_uri.media_id == updated_mxc_uri.media_id
        assert os.path.exists(os.path.join("media", SMALL_PNG_SHA256_PATH))
        assert isinstance(self.repo, MediaRepository)
        assert not os.path.exists(self.repo.filepaths.local_media_filepath(media_id))

    def test_copy_media_with_original_path(self) -> None:
        """Test that `copy_media` function can copy media with original path"""
        # Confirm that the sha256 path does not exists yet
        expected_path = os.path.join("media", SMALL_PNG_SHA256_PATH)
        assert not os.path.exists(expected_path)
        # Create media with original path
        original_mxc_uri = self._create_media_with_original_path(self.creator)
        assert isinstance(self.repo, MediaRepository)
        # Copy the media with the original path
        copied_mxc_uri = self.get_success(
            self.repo.copy_media(
                original_mxc_uri, UserID.from_string(self.creator), 1000
            )
        )
        assert copied_mxc_uri.media_id != original_mxc_uri.media_id
        # TODO: Copy should not remove the original media.
        assert os.path.exists(
            self.repo.filepaths.local_media_filepath(original_mxc_uri.media_id)
        )
        assert os.path.exists(os.path.join("media", SMALL_PNG_SHA256_PATH))
        # Make sure the new media is only created with sha256 path and not using the old path
        assert not os.path.exists(
            self.repo.filepaths.local_media_filepath(copied_mxc_uri.media_id)
        )

    def test_copy_media_with_sha256_path(self) -> None:
        # Create media with sha256 path
        original_mxc_uri = self._create_media_with_sha256_path(self.creator)

        # Copy the media with the original path
        copied_mxc_uri = self.get_success(
            self.repo.copy_media(
                original_mxc_uri, UserID.from_string(self.creator), 1000
            )
        )
        assert copied_mxc_uri.media_id != original_mxc_uri.media_id
        assert os.path.exists(os.path.join("media", SMALL_PNG_SHA256_PATH))
        # Make sure the new media is only created with sha256 path and not using the media_id path
        assert isinstance(self.repo, MediaRepository)
        assert not os.path.exists(
            self.repo.filepaths.local_media_filepath(copied_mxc_uri.media_id)
        )

    def test_get_local_media_with_sha256_path(self) -> None:
        """Test that `get_local_media` can fetch the media with the sha256 path successfully"""
        # Generate the path with sha256
        mxc_uri = self._create_media_with_sha256_path(self.creator)

        # Make sure the media is only created with sha256 path
        assert isinstance(self.repo, MediaRepository)
        assert not os.path.exists(
            self.repo.filepaths.local_media_filepath(mxc_uri.media_id)
        )
        # try `get_local_media` can fetch the media with the sha256 path successfully
        # Test via HTTP request
        channel = self.make_request(
            "GET",
            f"/_matrix/client/v1/media/download/{self.hs.hostname}/{mxc_uri.media_id}",
            access_token=self.creator_tok,
        )

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], SMALL_PNG)

    def test_get_remote_media_impl_with_sha256_path_cache_hit(self) -> None:
        server_name = "other_server.com"
        # Generate remote media with media_id path
        media_id = self._create_remote_media_with_sha256_path(server_name)

        assert isinstance(self.repo, MediaRepository)
        responder, remote_media = self.get_success(
            self.repo._get_remote_media_impl(
                server_name,
                media_id,
                1000,
                AsyncMock(),
                "127.0.0.1",
                False,
                True,
            )
        )

        assert responder is not None
        assert isinstance(responder, FileResponder)
        responder.open_file.seek(0)
        content = responder.open_file.read()
        assert content == SMALL_PNG
        assert remote_media is not None
        assert remote_media.media_id == media_id
        assert remote_media.media_length == 67
        assert remote_media.upload_name == "other_server_media"
        assert remote_media.sha256 == SMALL_PNG_SHA256

    def test_get_remote_media_impl_with_sha256_path_cache_miss_no_federation(
        self,
    ) -> None:
        async def _mock_download_media(
            destination: str,
            media_id: str,
            output_stream: BinaryIO,
            max_size: int,
            max_timeout_ms: int,
            download_ratelimiter: "Ratelimiter",
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

        self.repo.client.download_media = _mock_download_media  # type: ignore
        server_name = "other_server.com"
        media_id = random_string(24)  # remote server's media id
        max_timeout_ms = 1000
        ratelimiter = AsyncMock()
        ip_address = "127.0.0.1"
        # Call the method
        assert isinstance(self.repo, MediaRepository)
        responder, media_info = self.get_success(
            self.repo._get_remote_media_impl(
                server_name=server_name,
                media_id=media_id,
                max_timeout_ms=max_timeout_ms,
                download_ratelimiter=ratelimiter,
                ip_address=ip_address,
                use_federation_endpoint=False,
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

        # check if the file is saved in the media cache table
        remote_media = self.get_success(
            self.repo.store.get_cached_remote_media(server_name, media_id)
        )
        assert remote_media is not None

        # check if the file is saved in the media store
        assert os.path.exists(self.repo.filepaths.filepath_sha(SMALL_PNG_SHA256))

        # check if the thumbnails are generated
        assert os.path.exists(self.repo.filepaths.thumbnail_sha_dir(SMALL_PNG_SHA256))
        thumbnail = self.get_success(
            self.repo.store.get_remote_media_thumbnail(
                server_name, media_id, 1, 1, "image/png"
            )
        )
        assert thumbnail is not None

    def test_remove_local_media_from_disk_with_original_path(self) -> None:
        # generate 2 media with media_id path
        media1_mxc = self._create_media_with_original_path(self.creator)
        media1_id = media1_mxc.media_id
        media2_mxc = self._create_media_with_original_path(self.creator)
        media2_id = media2_mxc.media_id

        assert isinstance(self.repo, MediaRepository)
        removed_media_id, total = self.get_success(
            self.repo._remove_local_media_from_disk([media1_id, media2_id])
        )
        assert removed_media_id == [media1_id, media2_id]
        assert total == 2
        assert not os.path.exists(self.repo.filepaths.local_media_filepath(media1_id))
        assert not os.path.exists(self.repo.filepaths.local_media_filepath(media2_id))

    def test_remove_local_media_from_disk_with_sha256_path(self) -> None:
        # generate 2 media with media_id path
        # using actually same image, so there should be 2 rows in the table
        # but only 1 media stored in filesystem.
        media1_mxc = self._create_media_with_sha256_path(self.creator)
        media1_id = media1_mxc.media_id
        media2_mxc = self._create_media_with_sha256_path(self.creator)
        media2_id = media2_mxc.media_id

        assert isinstance(self.repo, MediaRepository)
        removed_media_id, total = self.get_success(
            self.repo._remove_local_media_from_disk([media1_id, media2_id])
        )
        assert removed_media_id == [media1_id, media2_id]
        assert total == 2
        assert not os.path.exists(os.path.join("media", SMALL_PNG_SHA256_PATH))
