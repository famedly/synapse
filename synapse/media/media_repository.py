#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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
import contextlib
import errno
import logging
import os
import shutil
from io import BytesIO
from typing import IO, TYPE_CHECKING

import attr
from matrix_common.types.mxc_uri import MXCUri

import twisted.web.http
from twisted.internet.defer import Deferred

from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
    UserLimitExceededError,
    cs_error,
)
from synapse.api.ratelimiting import Ratelimiter
from synapse.config.repository import ThumbnailRequirement
from synapse.http.server import respond_with_json
from synapse.http.site import SynapseRequest
from synapse.logging.context import defer_to_thread
from synapse.logging.opentracing import trace
from synapse.media._base import (
    FileInfo,
    Responder,
    ThumbnailInfo,
    check_for_cached_entry_and_respond,
    get_filename_from_headers,
    respond_404,
    respond_with_multipart_responder,
    respond_with_responder,
)
from synapse.media.filepath import MediaFilePaths
from synapse.media.media_storage import (
    SHA256_FILES_LOCK_NAME,
    MediaStorage,
    SHA256TransparentIOWriter,
)
from synapse.media.storage_provider import (
    FileStorageProviderBackend,
    StorageProviderWrapper,
)
from synapse.media.thumbnailer import (
    ANIMATED_THUMBNAIL_TYPE,
    Thumbnailer,
    ThumbnailError,
)
from synapse.media.url_previewer import UrlPreviewer
from synapse.storage.databases.main.media_repository import LocalMedia, RemoteMedia
from synapse.types import UserID
from synapse.util.async_helpers import Linearizer
from synapse.util.duration import Duration
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.handlers.worker_lock import WaitingLock
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# How often to run the background job to update the "recently accessed"
# attribute of local and remote media.
UPDATE_RECENTLY_ACCESSED_TS = Duration(minutes=1)
# How often to run the background job to check for local and remote media
# that should be purged according to the configured media retention settings.
MEDIA_RETENTION_CHECK_PERIOD = Duration(hours=1)
MEDIA_TEMP_FILE_CLEANUP_PERIOD = Duration(hours=1)


class MediaRepository:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.client = hs.get_federation_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastores().main
        self.max_upload_size = hs.config.media.max_upload_size
        self.max_image_pixels = hs.config.media.max_image_pixels
        self.unused_expiration_time = hs.config.media.unused_expiration_time
        self.max_pending_media_uploads = hs.config.media.max_pending_media_uploads

        Thumbnailer.set_limits(self.max_image_pixels)

        self.primary_base_path: str = hs.config.media.media_store_path
        self.filepaths: MediaFilePaths = MediaFilePaths(self.primary_base_path)

        self.dynamic_thumbnails = hs.config.media.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.media.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote", clock=self.clock)
        self._worker_locks = hs.get_worker_locks_handler()

        self.recently_accessed_remotes: set[tuple[str, str]] = set()
        self.recently_accessed_locals: set[str] = set()

        self.federation_domain_whitelist = (
            hs.config.federation.federation_domain_whitelist
        )
        self.prevent_media_downloads_from = hs.config.media.prevent_media_downloads_from

        self.download_ratelimiter = Ratelimiter(
            store=hs.get_storage_controllers().main,
            clock=hs.get_clock(),
            cfg=hs.config.ratelimiting.remote_media_downloads,
        )

        # List of StorageProviders where we should search for media and
        # potentially upload to.
        storage_providers = []

        for (
            clz,
            provider_config,
            wrapper_config,
        ) in hs.config.media.media_storage_providers:
            backend = clz(hs, provider_config)
            provider = StorageProviderWrapper(
                backend,
                store_local=wrapper_config.store_local,
                store_remote=wrapper_config.store_remote,
                store_synchronous=wrapper_config.store_synchronous,
            )
            storage_providers.append(provider)

        # If local media storage is enabled, create the local provider
        local_provider: FileStorageProviderBackend | None = None
        if hs.config.media.enable_local_media_storage and self.primary_base_path:
            local_provider = FileStorageProviderBackend(hs, self.primary_base_path)

        self.media_storage: MediaStorage = MediaStorage(
            self.hs, self.filepaths, storage_providers, local_provider
        )

        # Log a warning if there are no storage backends configured
        if not hs.config.media.enable_local_media_storage and not storage_providers:
            logger.warning(
                "Local media storage is disabled and no media_storage_providers are "
                "configured. All media requests will return 404 errors as there is "
                "no storage backend available."
            )

        self.clock.looping_call(
            self._start_update_recently_accessed, UPDATE_RECENTLY_ACCESSED_TS
        )
        if hs.config.worker.run_background_tasks:
            self.clock.looping_call(
                self._start_cleanup_stale_media_temporary_files,
                MEDIA_TEMP_FILE_CLEANUP_PERIOD,
            )

        # Media retention configuration options
        self._media_retention_local_media_lifetime_ms = (
            hs.config.media.media_retention_local_media_lifetime_ms
        )
        self._media_retention_remote_media_lifetime_ms = (
            hs.config.media.media_retention_remote_media_lifetime_ms
        )

        # Check whether local or remote media retention is configured
        if (
            hs.config.media.media_retention_local_media_lifetime_ms is not None
            or hs.config.media.media_retention_remote_media_lifetime_ms is not None
        ):
            # Run the background job to apply media retention rules routinely,
            # with the duration between runs dictated by the homeserver config.
            self.clock.looping_call(
                self._start_apply_media_retention_rules,
                MEDIA_RETENTION_CHECK_PERIOD,
            )

        if hs.config.media.url_preview_enabled:
            self.url_previewer: UrlPreviewer | None = UrlPreviewer(
                hs, self, self.media_storage
            )
        else:
            self.url_previewer = None

        # We get the media upload limits and sort them in descending order of
        # time period, so that we can apply some optimizations.
        self.default_media_upload_limits = hs.config.media.media_upload_limits
        self.default_media_upload_limits.sort(
            key=lambda limit: limit.time_period_ms, reverse=True
        )

        self.media_repository_callbacks = hs.get_module_api_callbacks().media_repository

    def _start_update_recently_accessed(self) -> Deferred:
        return self.hs.run_as_background_process(
            "update_recently_accessed_media",
            self._update_recently_accessed,
        )

    def _start_cleanup_stale_media_temporary_files(self) -> Deferred:
        return self.hs.run_as_background_process(
            "cleanup_stale_media_temporary_files",
            self.media_storage.cleanup_stale_temporary_files,
        )

    def _start_apply_media_retention_rules(self) -> Deferred:
        return self.hs.run_as_background_process(
            "apply_media_retention_rules",
            self._apply_media_retention_rules,
        )

    async def _update_recently_accessed(self) -> None:
        remote_media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        local_media = self.recently_accessed_locals
        self.recently_accessed_locals = set()

        await self.store.update_cached_last_access_time(
            local_media, remote_media, self.clock.time_msec()
        )

    def mark_recently_accessed(self, server_name: str | None, media_id: str) -> None:
        """Mark the given media as recently accessed.

        Args:
            server_name: Origin server of media, or None if local
            media_id: The media ID of the content
        """
        if server_name:
            self.recently_accessed_remotes.add((server_name, media_id))
        else:
            self.recently_accessed_locals.add(media_id)

    @trace
    async def create_media_id(self, auth_user: UserID) -> tuple[str, int]:
        """Create and store a media ID for a local user and return the MXC URI and its
        expiration.

        Args:
            auth_user: The user_id of the uploader

        Returns:
            A tuple containing the MXC URI of the stored content and the timestamp at
            which the MXC URI expires.
        """
        media_id = random_string(24)
        now = self.clock.time_msec()
        await self.store.store_local_media_id(
            media_id=media_id,
            time_now_ms=now,
            user_id=auth_user,
        )
        return f"mxc://{self.server_name}/{media_id}", now + self.unused_expiration_time

    @trace
    async def reached_pending_media_limit(self, auth_user: UserID) -> tuple[bool, int]:
        """Check if the user is over the limit for pending media uploads.

        Args:
            auth_user: The user_id of the uploader

        Returns:
            A tuple with a boolean and an integer indicating whether the user has too
            many pending media uploads and the timestamp at which the first pending
            media will expire, respectively.
        """
        pending, first_expiration_ts = await self.store.count_pending_media(
            user_id=auth_user
        )
        return pending >= self.max_pending_media_uploads, first_expiration_ts

    @trace
    async def verify_can_upload(self, media_id: str, auth_user: UserID) -> None:
        """Verify that the media ID can be uploaded to by the given user. This
        function checks that:

        * the media ID exists
        * the media ID does not already have content
        * the user uploading is the same as the one who created the media ID
        * the media ID has not expired

        Args:
            media_id: The media ID to verify
            auth_user: The user_id of the uploader
        """
        media = await self.store.get_local_media(media_id)
        if media is None:
            raise NotFoundError("Unknown media ID")

        if media.user_id != auth_user.to_string():
            raise SynapseError(
                403,
                "Only the creator of the media ID can upload to it",
                errcode=Codes.FORBIDDEN,
            )

        if media.media_length is not None:
            raise SynapseError(
                409,
                "Media ID already has content",
                errcode=Codes.CANNOT_OVERWRITE_MEDIA,
            )

        expired_time_ms = self.clock.time_msec() - self.unused_expiration_time
        if media.created_ts < expired_time_ms:
            raise NotFoundError("Media ID has expired")

    def _lock_sha256_files(self, server_name: str | None, sha256: str) -> "WaitingLock":
        """A cross-worker lock on the files stored under a SHA-256 path.

        New media must hold this lock before rename the temporary file into its
        final SHA-256 path, until the DB row is inserted. Deletion must hold this lock
        while checking references and removing files. Otherwise deletion could remove a
        file whose DB row is about to be inserted.

        Args:
            server_name: The origin of remote media, or None for local media.
            sha256: The SHA-256 of the media.
        """
        return self._worker_locks.acquire_lock(
            SHA256_FILES_LOCK_NAME, f"{server_name or ''}/{sha256}"
        )

    async def _lock_sha256_for_new_media(
        self,
        sha256_lock: contextlib.AsyncExitStack,
        server_name: str | None,
        sha256: str,
    ) -> bool:
        """Acquire the SHA-256 lock for new media, and check whether storing it
        creates its SHA-256 file.

        The lock is entered on `sha256_lock`, so it stays held until that stack
        exits, after the DB row is written. Call this inside the `store_into_file`
        block, after the body is hashed and before the block exits and renames the
        temporary file onto the SHA-256 path. The existence check runs under the
        lock, so no other new media can create the file in between.

        Args:
            sha256_lock: The exit stack that holds the lock until the DB row exists.
            server_name: The origin of remote media, or None for local media.
            sha256: The SHA-256 of the media.

        Returns:
            Whether the local media store has no file at the SHA-256 path yet, so
            this media creates it and older media-ID copies can be cleaned up.
            Always False without a local media store, as there are no local
            media-ID copies to clean up then.
        """
        # Acquired now, released when `sha256_lock` exits. Another worker storing or
        # deleting the same hash waits on the same lock.
        await sha256_lock.enter_async_context(
            self._lock_sha256_files(server_name, sha256)
        )

        if not self.media_storage.local_provider:
            return False
        exists = await defer_to_thread(
            self.hs.get_reactor(),
            os.path.exists,
            self._media_filepath(server_name, sha256),
        )
        return not exists

    @trace
    async def create_or_update_content(
        self,
        media_type: str,
        upload_name: str | None,
        content: IO,
        content_length: int,
        auth_user: UserID,
        media_id: str | None = None,
    ) -> MXCUri:
        """Create or update the content of the given media ID.

        Args:
            media_type: The content type of the file.
            upload_name: The name of the file, if provided.
            content: A file like object that is the content to store
            content_length: The length of the content
            auth_user: The user_id of the uploader
            media_id: The media ID to update if provided, otherwise creates
                new media ID.

        Returns:
            The mxc url of the stored content
        """

        is_new_media = media_id is None
        if media_id is None:
            media_id = random_string(24)

        file_info = FileInfo(server_name=None, file_id=media_id)

        # Hold the lock before renaming the temporary file onto its final SHA-256 path
        # until the DB row is inserted. Quarantine and quota checks run before renaming,
        # so a failure deletes only the temporary file.
        # The lock key includes the hash, so it cannot be opened before the file is
        # written, and it has to stay held after store_into_file finishes.
        async with contextlib.AsyncExitStack() as sha256_lock:
            # Creates a temporary file and yields it. For a new upload the path is not
            # known yet, so the body receives a SHA256TransparentIOWriter
            async with self.media_storage.store_into_file(file_info) as (f, _):
                sha256writer = SHA256TransparentIOWriter.get_or_wrap(f)
                # This implements all of BinaryIO as it has a passthrough
                await self.media_storage.write_to_file(content, sha256writer.wrap())
                sha256 = sha256writer.hexdigest()
                should_quarantine = await self.store.get_is_hash_quarantined(sha256)

                if should_quarantine:
                    logger.warning(
                        "Media has been automatically quarantined as it matched existing quarantined media"
                    )

                # Check that the user has not exceeded any of the media upload limits.
                # A failure here never acquires the lock. The exception is thrown back
                # into `store_into_file` at the yield, which deletes the temporary file.
                await self._check_media_upload_limits(auth_user, content_length)

                # The SHA-256 lock is acquired after the bytes are hashed and released
                # only after the database row exists. Renaming the temporary file onto
                # the SHA-256 path happens in between, while the lock is held. Also
                # record whether this upload creates the SHA-256 file.
                creates_sha256_file = await self._lock_sha256_for_new_media(
                    sha256_lock, None, sha256
                )

            # Within `store_into_file`, the temporary file is closed and the spam check
            # is ran, and the temporary file is renamed onto the SHA-256 path only when
            # that path is absent. An existing file is kept. Storage providers are given
            # the path only when this attempt created it. A spam failure deletes the
            # temporary file.

            logger.info("Stored local media %s with SHA-256 %s", media_id, sha256)

            if is_new_media:
                await self.store.store_local_media(
                    media_id=media_id,
                    media_type=media_type,
                    time_now_ms=self.clock.time_msec(),
                    upload_name=upload_name,
                    media_length=content_length,
                    user_id=auth_user,
                    sha256=sha256,
                    quarantined_by="system" if should_quarantine else None,
                )
            else:
                await self.store.update_local_media(
                    media_id=media_id,
                    media_type=media_type,
                    upload_name=upload_name,
                    media_length=content_length,
                    user_id=auth_user,
                    sha256=sha256,
                    quarantined_by="system" if should_quarantine else None,
                )
            # The database insert or update runs with the lock still held, so a
            # concurrent deletion can see this row before it decides the hash file is
            # unused.

        if creates_sha256_file:
            # The SHA-256 file is new, so older media with the same content may
            # still have their own copy at a media-ID path. Remove those copies.
            await self._remove_media_id_files_with_sha256(None, sha256)

        try:
            # Now the lock is released, thumbnail generation runs after.
            await self._generate_thumbnails(
                None, media_id, media_id, media_type, sha256=sha256
            )
        except Exception as e:
            logger.info("Failed to generate thumbnails: %s", e)

        return MXCUri(self.server_name, media_id)

    async def _check_media_upload_limits(
        self, auth_user: UserID, content_length: int
    ) -> None:
        """Raise if this upload would exceed the user's media quota.

        Runs before the temporary upload is renamed to its final SHA-256 path, so a
        failure leaves no SHA-256 file behind.
        """
        # Use limits from module API if provided
        media_upload_limits = (
            await self.media_repository_callbacks.get_media_upload_limits_for_user(
                auth_user.to_string()
            )
        )

        # Otherwise use the default limits from config
        if media_upload_limits is None:
            # Note: the media upload limits are sorted so larger time periods are
            # first.
            media_upload_limits = self.default_media_upload_limits

        # This is the total size of media uploaded by the user in the last
        # `time_period_ms` milliseconds, or None if we haven't checked yet.
        uploaded_media_size: int | None = None

        for limit in media_upload_limits:
            # We only need to check the amount of media uploaded by the user in
            # this latest (smaller) time period if the amount of media uploaded
            # in a previous (larger) time period is below the limit.
            #
            # This optimization means that in the common case where the user
            # hasn't uploaded much media, we only need to query the database
            # once.
            if (
                uploaded_media_size is None
                or uploaded_media_size + content_length > limit.max_bytes
            ):
                uploaded_media_size = await self.store.get_media_uploaded_size_for_user(
                    user_id=auth_user.to_string(), time_period_ms=limit.time_period_ms
                )

            if uploaded_media_size + content_length > limit.max_bytes:
                await self.media_repository_callbacks.on_media_upload_limit_exceeded(
                    user_id=auth_user.to_string(),
                    limit=limit,
                    sent_bytes=uploaded_media_size,
                    attempted_bytes=content_length,
                )

                # Fall back to the static page served by Synapse when the limit
                # doesn't specify its own `info_uri` (e.g. limits returned by a
                # module callback without one).
                info_uri = (
                    limit.info_uri
                    or self.hs.config.media.media_upload_limit_fallback_info_uri
                )

                raise UserLimitExceededError(
                    403,
                    "Media upload limit exceeded",
                    info_uri=info_uri,
                    can_upgrade=limit.can_upgrade,
                )

    def respond_not_yet_uploaded(self, request: SynapseRequest) -> None:
        respond_with_json(
            request,
            504,
            cs_error("Media has not been uploaded yet", code=Codes.NOT_YET_UPLOADED),
            send_cors=True,
        )

    async def get_cached_remote_media_info(
        self, origin: str, media_id: str
    ) -> RemoteMedia | None:
        """
        Get cached remote media info for a given origin/media ID combo. If the requested
        media is not found locally, it will not be requested over federation and the
        call will return None.

        Args:
            origin: The origin of the remote media
            media_id: The media ID of the requested content

        Returns:
            The info for the cached remote media or None if it was not found
        """
        return await self.store.get_cached_remote_media(origin, media_id)

    async def get_local_media_info(
        self,
        request: SynapseRequest,
        media_id: str,
        max_timeout_ms: int,
        bypass_quarantine: bool = False,
    ) -> LocalMedia | None:
        """Gets the info dictionary for given local media ID. If the media has
        not been uploaded yet, this function will wait up to ``max_timeout_ms``
        milliseconds for the media to be uploaded.

        Args:
            request: The incoming request.
            media_id: The media ID of the content. (This is the same as
                the file_id for local content.)
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            bypass_quarantine: whether to bypass quarantine checks

        Returns:
            Either the info dictionary for the given local media ID or
            ``None``. If ``None``, then no further processing is necessary as
            this function will send the necessary JSON response.
        """
        wait_until = self.clock.time_msec() + max_timeout_ms
        while True:
            # Get the info for the media
            media_info = await self.store.get_local_media(media_id)
            if not media_info:
                logger.info("Media %s is unknown", media_id)
                respond_404(request)
                return None

            if media_info.quarantined_by and not bypass_quarantine:
                logger.info("Media %s is quarantined", media_id)
                respond_404(request)
                return None

            # The file has been uploaded, so stop looping
            if media_info.media_length is not None:
                return media_info

            # Check if the media ID has expired and still hasn't been uploaded to.
            now = self.clock.time_msec()
            expired_time_ms = now - self.unused_expiration_time
            if media_info.created_ts < expired_time_ms:
                logger.info("Media %s has expired without being uploaded", media_id)
                respond_404(request)
                return None

            if now >= wait_until:
                break

            await self.clock.sleep(Duration(milliseconds=500))

        logger.info("Media %s has not yet been uploaded", media_id)
        self.respond_not_yet_uploaded(request)
        return None

    async def get_local_media(
        self,
        request: SynapseRequest,
        media_id: str,
        name: str | None,
        max_timeout_ms: int,
        allow_authenticated: bool = True,
        federation: bool = False,
        bypass_quarantine: bool = False,
    ) -> None:
        """Responds to requests for local media, if exists, or returns 404.

        Args:
            request: The incoming request.
            media_id: The media ID of the content. (This is the same as
                the file_id for local content.)
            name: Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            allow_authenticated: whether media marked as authenticated may be served to this request
            federation: whether the local media being fetched is for a federation request
            bypass_quarantine: whether to bypass quarantine checks

        Returns:
            Resolves once a response has successfully been written to request
        """
        media_info = await self.get_local_media_info(
            request, media_id, max_timeout_ms, bypass_quarantine=bypass_quarantine
        )
        if not media_info:
            return

        if self.hs.config.media.enable_authenticated_media and not allow_authenticated:
            if media_info.authenticated:
                raise NotFoundError()

        self.mark_recently_accessed(None, media_id)

        # Once we've checked auth we can return early if the media is cached on
        # the client
        if check_for_cached_entry_and_respond(request):
            return

        media_type = media_info.media_type
        if not media_type:
            media_type = "application/octet-stream"
        media_length = media_info.media_length
        upload_name = name if name else media_info.upload_name
        url_cache = media_info.url_cache

        file_info = FileInfo(
            None, media_id, url_cache=bool(url_cache), sha256=media_info.sha256
        )

        responder = await self.media_storage.fetch_media(file_info)
        if federation:
            await respond_with_multipart_responder(
                self.clock, request, responder, media_type, media_length, upload_name
            )
        else:
            await respond_with_responder(
                request, responder, media_type, media_length, upload_name
            )

    async def get_remote_media(
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        name: str | None,
        max_timeout_ms: int,
        ip_address: str,
        use_federation_endpoint: bool,
        allow_authenticated: bool = True,
        bypass_quarantine: bool = False,
    ) -> None:
        """Respond to requests for remote media.

        Args:
            request: The incoming request.
            server_name: Remote server_name where the media originated.
            media_id: The media ID of the content (as defined by the remote server).
            name: Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            ip_address: the IP address of the requester
            use_federation_endpoint: whether to request the remote media over the new
                federation `/download` endpoint
            allow_authenticated: whether media marked as authenticated may be served to this
                request
            bypass_quarantine: whether to bypass quarantine checks

        Returns:
            Resolves once a response has successfully been written to request
        """
        if (
            self.federation_domain_whitelist is not None
            and server_name not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(server_name)

        # Don't let users download media from domains listed in the config, even
        # if we might have the media to serve. This is Trust & Safety tooling to
        # block some servers' media from being accessible to local users.
        # See `prevent_media_downloads_from` config docs for more info.
        if server_name in self.prevent_media_downloads_from:
            respond_404(request)
            return

        self.mark_recently_accessed(server_name, media_id)

        # We linearize here to ensure that we don't try and download remote
        # media multiple times concurrently
        key = (server_name, media_id)
        async with self.remote_media_linearizer.queue(key):
            responder, media_info = await self._get_remote_media_impl(
                server_name,
                media_id,
                max_timeout_ms,
                self.download_ratelimiter,
                ip_address,
                use_federation_endpoint,
                allow_authenticated,
                bypass_quarantine=bypass_quarantine,
            )

        # Check if the media is cached on the client, if so return 304. We need
        # to do this after we have fetched remote media, as we need it to do the
        # auth.
        if check_for_cached_entry_and_respond(request):
            # We always need to use the responder.
            if responder:
                with responder:
                    pass

            return

        # We deliberately stream the file outside the lock
        if responder and media_info:
            upload_name = name if name else media_info.upload_name
            await respond_with_responder(
                request,
                responder,
                media_info.media_type,
                media_info.media_length,
                upload_name,
            )
        else:
            respond_404(request)

    async def get_remote_media_info(
        self,
        server_name: str,
        media_id: str,
        max_timeout_ms: int,
        ip_address: str,
        use_federation: bool,
        allow_authenticated: bool,
    ) -> RemoteMedia:
        """Gets the media info associated with the remote file, downloading
        if necessary.

        Args:
            server_name: Remote server_name where the media originated.
            media_id: The media ID of the content (as defined by the remote server).
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            ip_address: IP address of the requester
            use_federation: if a download is necessary, whether to request the remote file
                over the federation `/download` endpoint
            allow_authenticated: whether media marked as authenticated may be served to this
                request

        Returns:
            The media info of the file
        """
        if (
            self.federation_domain_whitelist is not None
            and server_name not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(server_name)

        # We linearize here to ensure that we don't try and download remote
        # media multiple times concurrently
        key = (server_name, media_id)
        async with self.remote_media_linearizer.queue(key):
            responder, media_info = await self._get_remote_media_impl(
                server_name,
                media_id,
                max_timeout_ms,
                self.download_ratelimiter,
                ip_address,
                use_federation,
                allow_authenticated,
            )

        # Ensure we actually use the responder so that it releases resources
        if responder:
            with responder:
                pass

        return media_info

    async def _get_remote_media_impl(
        self,
        server_name: str,
        media_id: str,
        max_timeout_ms: int,
        download_ratelimiter: Ratelimiter,
        ip_address: str,
        use_federation_endpoint: bool,
        allow_authenticated: bool,
        bypass_quarantine: bool = False,
    ) -> tuple[Responder | None, RemoteMedia]:
        """Looks for media in local cache, if not there then attempt to
        download from remote server.

        Args:
            server_name: Remote server_name where the media originated.
            media_id: The media ID of the content (as defined by the
                remote server).
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            download_ratelimiter: a ratelimiter limiting remote media downloads, keyed to
                requester IP.
            ip_address: the IP address of the requester
            use_federation_endpoint: whether to request the remote media over the new federation
            /download endpoint
            bypass_quarantine: whether to bypass quarantine checks

        Returns:
            A tuple of responder and the media info of the file.
        """
        media_info = await self.store.get_cached_remote_media(server_name, media_id)

        if self.hs.config.media.enable_authenticated_media and not allow_authenticated:
            # if it isn't cached then don't fetch it or if it's authenticated then don't serve it
            if not media_info or media_info.authenticated:
                raise NotFoundError()

        # file_id is the ID we use to track the file locally. If we've already
        # seen the file then reuse the existing ID, otherwise generate a new
        # one.

        # If we have an entry in the DB, try and look for it
        if media_info:
            file_id = media_info.filesystem_id
            file_info = FileInfo(server_name, file_id, sha256=media_info.sha256)

            if media_info.quarantined_by and not bypass_quarantine:
                logger.info("Media is quarantined")
                raise NotFoundError()

            if not media_info.media_type:
                media_info = attr.evolve(
                    media_info, media_type="application/octet-stream"
                )

            responder = await self.media_storage.fetch_media(file_info)
            if responder:
                return responder, media_info

        # Failed to find the file anywhere, lets download it.

        try:
            media_info = await self._download_remote_file(
                server_name,
                media_id,
                max_timeout_ms,
                download_ratelimiter,
                ip_address,
                use_federation_endpoint,
            )

        except SynapseError:
            raise
        except Exception as e:
            # If this is a constraint violation, it means another worker
            # downloaded the media first. We should fetch the existing media info.
            if isinstance(e, self.store.database_engine.module.IntegrityError):
                # The file has already been cleaned up in _download_remote_file
                # Just fetch the existing media info
                media_info = await self.store.get_cached_remote_media(
                    server_name, media_id
                )
                if not media_info:
                    # This shouldn't happen, but let's raise an error if it does
                    raise SynapseError(500, "Failed to fetch remote media")
            else:
                raise e

        file_id = media_info.filesystem_id
        if not media_info.media_type:
            media_info = attr.evolve(media_info, media_type="application/octet-stream")
        file_info = FileInfo(server_name, file_id, sha256=media_info.sha256)

        # We generate thumbnails even if another process downloaded the media
        # as a) it's conceivable that the other download request dies before it
        # generates thumbnails, but mainly b) we want to be sure the thumbnails
        # have finished being generated before responding to the client,
        # otherwise they'll request thumbnails and get a 404 if they're not
        # ready yet.
        await self._generate_thumbnails(
            server_name,
            media_id,
            file_id,
            media_info.media_type,
            sha256=media_info.sha256,
        )

        responder = await self.media_storage.fetch_media(file_info)
        return responder, media_info

    async def _download_remote_file(
        self,
        server_name: str,
        media_id: str,
        max_timeout_ms: int,
        download_ratelimiter: Ratelimiter,
        ip_address: str,
        use_federation_endpoint: bool,
    ) -> RemoteMedia:
        """Download remote media into a new file and record it.

        The SHA-256 lock is held from just before the temporary file is renamed onto
        its final SHA-256 path, until the database row is inserted.

        Args:
            server_name: Originating server
            media_id: The media ID of the content (as defined by the
                remote server). This is different than the file_id, which is
                locally generated.
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.
            download_ratelimiter: a ratelimiter limiting remote media downloads, keyed to
                requester IP
            ip_address: the IP address of the requester
            use_federation_endpoint: whether to download over the federation v1
                `/download` endpoint instead of the `_matrix/media` endpoint.

        Returns:
            The media info of the file.

        Raises:
            IntegrityError: another worker stored the same media first. Our file
                is already cleaned up.
        """

        file_id = random_string(24)

        file_info = FileInfo(server_name=server_name, file_id=file_id)

        async with contextlib.AsyncExitStack() as sha256_lock:
            async with self.media_storage.store_into_file(file_info) as (f, _fname):
                sha256writer = SHA256TransparentIOWriter.get_or_wrap(f)
                try:
                    if use_federation_endpoint:
                        res = await self.client.federation_download_media(
                            server_name,
                            media_id,
                            # This implements all of BinaryIO as it has a passthrough
                            output_stream=sha256writer.wrap(),
                            max_size=self.max_upload_size,
                            max_timeout_ms=max_timeout_ms,
                            download_ratelimiter=download_ratelimiter,
                            ip_address=ip_address,
                        )
                        # A fallback to the _matrix/media endpoint returns only
                        # length and headers, without the JSON metadata part.
                        length, headers = res[0], res[1]
                    else:
                        length, headers = await self.client.download_media(
                            server_name,
                            media_id,
                            # This implements all of BinaryIO as it has a passthrough
                            output_stream=sha256writer.wrap(),
                            max_size=self.max_upload_size,
                            max_timeout_ms=max_timeout_ms,
                            download_ratelimiter=download_ratelimiter,
                            ip_address=ip_address,
                        )
                except RequestSendFailed as e:
                    logger.warning(
                        "Request failed fetching remote media %s/%s: %r",
                        server_name,
                        media_id,
                        e,
                    )
                    raise SynapseError(502, "Failed to fetch remote media")

                except HttpResponseException as e:
                    logger.warning(
                        "HTTP error fetching remote media %s/%s: %s",
                        server_name,
                        media_id,
                        e.response,
                    )
                    if e.code == twisted.web.http.NOT_FOUND:
                        raise e.to_synapse_error()
                    raise SynapseError(502, "Failed to fetch remote media")

                except SynapseError:
                    logger.warning(
                        "Failed to fetch remote media %s/%s", server_name, media_id
                    )
                    raise
                except NotRetryingDestination:
                    logger.warning("Not retrying destination %r", server_name)
                    raise SynapseError(502, "Failed to fetch remote media")
                except Exception:
                    logger.exception(
                        "Failed to fetch remote media %s/%s", server_name, media_id
                    )
                    raise SynapseError(502, "Failed to fetch remote media")

                if b"Content-Type" in headers:
                    media_type = headers[b"Content-Type"][0].decode("ascii")
                else:
                    media_type = "application/octet-stream"
                upload_name = get_filename_from_headers(headers)
                time_now_ms = self.clock.time_msec()
                sha256 = sha256writer.hexdigest()

                # The temporary file is renamed to its final SHA-256 path when this
                # block exits, under the SHA-256 lock acquired here. Also record
                # whether this download creates the SHA-256 file.
                creates_sha256_file = await self._lock_sha256_for_new_media(
                    sha256_lock, server_name, sha256
                )

            # Multiple remote media download requests can race (when using
            # multiple media repos), so this may throw a violation constraint
            # exception. If it does we'll delete the newly downloaded file from
            # disk. This already holds the SHA-256 lock.
            try:
                await self.store.store_cached_remote_media(
                    origin=server_name,
                    media_id=media_id,
                    media_type=media_type,
                    time_now_ms=time_now_ms,
                    upload_name=upload_name,
                    media_length=length,
                    filesystem_id=file_id,
                    sha256=sha256,
                )
            except self.store.database_engine.module.IntegrityError:
                # Another worker downloaded the media first. Clean up our file,
                # unless other media shares its SHA-256 path. Re-raise so
                # `_get_remote_media_impl` reads the other worker's row.
                await self._remove_sha256_files_if_unused(server_name, sha256)
                raise

        logger.info(
            "Stored remote media %s/%s with SHA-256 %s",
            server_name,
            media_id,
            sha256,
        )

        if creates_sha256_file:
            # The SHA-256 file is new, so older media from the same origin with the
            # same content may still have their own copy at a `filesystem_id` path.
            # Remove those copies.
            await self._remove_media_id_files_with_sha256(server_name, sha256)

        return RemoteMedia(
            media_origin=server_name,
            media_id=media_id,
            media_type=media_type,
            media_length=length,
            upload_name=upload_name,
            created_ts=time_now_ms,
            filesystem_id=file_id,
            last_access_ts=time_now_ms,
            quarantined_by=None,
            authenticated=bool(self.hs.config.media.enable_authenticated_media),
            sha256=sha256,
        )

    def _get_thumbnail_requirements(
        self, media_type: str
    ) -> tuple[ThumbnailRequirement, ...]:
        scpos = media_type.find(";")
        if scpos > 0:
            media_type = media_type[:scpos]
        return self.thumbnail_requirements.get(media_type, ())

    def _get_thumbnail_source_size(
        self, thumbnailer: Thumbnailer
    ) -> tuple[int, int] | None:
        """Check the source image size and apply its EXIF orientation.

        Should be called from a thread, as transposing decodes the image.

        Returns:
            The (width, height) of the source image after transposing, or None if
            it is too large to thumbnail.
        """
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width,
                m_height,
                self.max_image_pixels,
            )
            return None

        if thumbnailer.transpose_method is not None:
            m_width, m_height = thumbnailer.transpose()
        return m_width, m_height

    def _generate_thumbnail_with_scale(
        self,
        thumbnailer: Thumbnailer,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        animated: bool = False,
    ) -> BytesIO | None:
        source_size = self._get_thumbnail_source_size(thumbnailer)
        if source_size is None:
            return None
        m_width, m_height = source_size

        if t_method == "crop":
            return thumbnailer.crop(t_width, t_height, t_type, animated=animated)
        elif t_method == "scale":
            t_width, t_height = thumbnailer.aspect(t_width, t_height)
            t_width = min(m_width, t_width)
            t_height = min(m_height, t_height)
            return thumbnailer.scale(t_width, t_height, t_type, animated=animated)

        return None

    async def generate_exact_thumbnail(
        self,
        server_name: str | None,
        file_id: str,
        media_id: str,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        url_cache: bool = False,
        animated: bool = False,
        sha256: str | None = None,
    ) -> tuple[str, FileInfo] | None:
        """Generate, store and record one thumbnail of exactly the given size.

        Args:
            server_name: The origin of remote media, or None for local media.
            file_id: The local file ID. Same as `media_id` for local media.
            media_id: The media ID of the content.
            t_width: The width of the thumbnail.
            t_height: The height of the thumbnail.
            t_method: The thumbnailing method, "crop" or "scale".
            t_type: The content type of the thumbnail.
            url_cache: Whether this is local media from the URL cache.
            animated: Whether to generate an animated thumbnail.
            sha256: The SHA-256 of the media, if known.

        Returns:
            The local path the thumbnail was written to and its file info, or None
            if the thumbnail could not be generated.
        """
        async with self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id, url_cache=url_cache, sha256=sha256)
        ) as input_path:
            try:
                thumbnailer = Thumbnailer(input_path)
            except ThumbnailError as e:
                logger.warning(
                    "Unable to generate a thumbnail for media %s from %s using a method of %s and type of %s: %s",
                    media_id,
                    server_name or "this server",
                    t_method,
                    t_type,
                    e,
                )
                return None

            with thumbnailer:
                t_byte_source = await defer_to_thread(
                    self.hs.get_reactor(),
                    self._generate_thumbnail_with_scale,
                    thumbnailer,
                    t_width,
                    t_height,
                    t_method,
                    t_type,
                    animated,
                )

        if not t_byte_source:
            # Could not generate thumbnail.
            return None

        return await self._store_thumbnail(
            server_name,
            media_id,
            file_id,
            url_cache,
            t_width,
            t_height,
            t_method,
            t_type,
            t_byte_source,
            sha256,
        )

    @trace
    async def _generate_thumbnails(
        self,
        server_name: str | None,
        media_id: str,
        file_id: str,
        media_type: str,
        url_cache: bool = False,
        sha256: str | None = None,
    ) -> dict | None:
        """Generate and store thumbnails for an image.

        Args:
            server_name: The server name if remote media, else None if local
            media_id: The media ID of the content. (This is the same as
                the file_id for local content)
            file_id: Local file ID
            media_type: The content type of the file
            url_cache: If we are thumbnailing images downloaded for the URL cache,
                used exclusively by the url previewer
            sha256: The SHA-256 of the media, if known

        Returns:
            Dict with "width" and "height" keys of original image, or None if the
            media cannot be thumbnailed or its thumbnails were copied from other
            media with the same SHA-256.
        """
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return None

        # Thumbnails of media with a SHA-256 are stored under the SHA-256 path, so
        # media with the same content shares the thumbnail files. If other media
        # already has thumbnails for this SHA-256, copy their DB rows instead of
        # decoding and re-encoding the image. URL cache files are not stored by
        # SHA-256, and the URL previewer needs the returned dimensions.
        #
        # Media stored before deduplication has its thumbnails at media-ID paths.
        # A copied row may then point at a missing SHA-256 thumbnail file, which is
        # regenerated on the first request, as for any thumbnail missing on disk.
        if (
            sha256
            and not url_cache
            and await self.store.copy_thumbnails_with_sha256(
                sha256, media_id, file_id, server_name
            )
        ):
            logger.debug(
                "Copied thumbnails of media %s from SHA-256 %s", media_id, sha256
            )
            return None

        async with self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id, url_cache=url_cache, sha256=sha256)
        ) as input_path:
            try:
                thumbnailer = Thumbnailer(input_path)
            except ThumbnailError as e:
                logger.warning(
                    "Unable to generate thumbnails for remote media %s from %s of type %s: %s",
                    media_id,
                    server_name,
                    media_type,
                    e,
                )
                return None

            with thumbnailer:
                source_size = await defer_to_thread(
                    self.hs.get_reactor(),
                    self._get_thumbnail_source_size,
                    thumbnailer,
                )
                if source_size is None:
                    return None
                m_width, m_height = source_size

                # JPEG has no alpha channel, so it would flatten a transparent
                # image onto a solid color background.
                needs_alpha = await defer_to_thread(
                    self.hs.get_reactor(), lambda: thumbnailer.has_transparency
                )

                # We deduplicate the thumbnail sizes by ignoring the cropped versions if
                # they have the same dimensions of a scaled one.
                thumbnails: dict[tuple[int, int, str], str] = {}
                for requirement in requirements:
                    t_type = requirement.media_type
                    if needs_alpha and t_type == "image/jpeg":
                        t_type = "image/png"

                    if requirement.method == "crop":
                        thumbnails.setdefault(
                            (requirement.width, requirement.height, t_type),
                            requirement.method,
                        )
                    elif requirement.method == "scale":
                        t_width, t_height = thumbnailer.aspect(
                            requirement.width, requirement.height
                        )
                        t_width = min(m_width, t_width)
                        t_height = min(m_height, t_height)
                        thumbnails[(t_width, t_height, t_type)] = requirement.method

                # Now we generate the thumbnails for each dimension, store it
                #
                # For animated source images we also generate and cache an
                # animated WebP thumbnail per (size, method), served only when a
                # client requests `?animated=true`. These are deduplicated since
                # the animated thumbnail is always WebP regardless of `t_type`.
                animated_done: set[tuple[int, int, str]] = set()
                for (t_width, t_height, t_type), t_method in thumbnails.items():
                    # Generate the thumbnail
                    if t_method == "crop":
                        t_byte_source = await defer_to_thread(
                            self.hs.get_reactor(),
                            thumbnailer.crop,
                            t_width,
                            t_height,
                            t_type,
                        )
                    elif t_method == "scale":
                        t_byte_source = await defer_to_thread(
                            self.hs.get_reactor(),
                            thumbnailer.scale,
                            t_width,
                            t_height,
                            t_type,
                        )
                    else:
                        logger.error("Unrecognized method: %r", t_method)
                        continue

                    if t_byte_source:
                        await self._store_thumbnail(
                            server_name,
                            media_id,
                            file_id,
                            url_cache,
                            t_width,
                            t_height,
                            t_method,
                            t_type,
                            t_byte_source,
                            sha256,
                        )

                    if (
                        thumbnailer.is_animated
                        and (t_width, t_height, t_method) not in animated_done
                    ):
                        animated_done.add((t_width, t_height, t_method))
                        a_byte_source = await defer_to_thread(
                            self.hs.get_reactor(),
                            thumbnailer.crop
                            if t_method == "crop"
                            else thumbnailer.scale,
                            t_width,
                            t_height,
                            ANIMATED_THUMBNAIL_TYPE,
                            True,
                        )
                        if a_byte_source:
                            await self._store_thumbnail(
                                server_name,
                                media_id,
                                file_id,
                                url_cache,
                                t_width,
                                t_height,
                                t_method,
                                ANIMATED_THUMBNAIL_TYPE,
                                a_byte_source,
                                sha256,
                            )

        return {"width": m_width, "height": m_height}

    async def _store_thumbnail(
        self,
        server_name: str | None,
        media_id: str,
        file_id: str,
        url_cache: bool,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        t_byte_source: BytesIO,
        sha256: str | None = None,
    ) -> tuple[str, FileInfo]:
        """Store a generated thumbnail in the media store, then record it in the
        database. Closes `t_byte_source`.

        The file is stored first, so a DB row never points at a thumbnail that
        failed to store, locally or in the storage providers.

        Args:
            server_name: The origin of remote media, or None for local media.
            media_id: The media ID of the content.
            file_id: The local file ID. Same as `media_id` for local media.
            url_cache: Whether this is local media from the URL cache.
            t_width: The width of the thumbnail.
            t_height: The height of the thumbnail.
            t_method: The thumbnailing method, "crop" or "scale".
            t_type: The content type of the thumbnail.
            t_byte_source: The generated thumbnail bytes.
            sha256: The SHA-256 of the media, if recorded. The thumbnail is stored
                under the SHA-256 path if set, otherwise under the media-ID path.

        Returns:
            The local path the thumbnail was written to, and its file info.
        """
        # The stored file holds exactly the generated bytes, so its length is known
        # without reading the file back. Reading it back would fail without a local
        # media store, where `store_file` returns an already removed temporary file.
        file_info = FileInfo(
            server_name=server_name,
            file_id=file_id,
            url_cache=url_cache,
            thumbnail=ThumbnailInfo(
                width=t_width,
                height=t_height,
                method=t_method,
                type=t_type,
                length=t_byte_source.getbuffer().nbytes,
            ),
            sha256=sha256,
        )
        assert file_info.thumbnail is not None
        t_len = file_info.thumbnail.length

        try:
            output_path = await self.media_storage.store_file(t_byte_source, file_info)
        finally:
            t_byte_source.close()

        logger.info("Stored thumbnail in file %r", output_path)

        if server_name:
            try:
                await self.store.store_remote_media_thumbnail(
                    server_name,
                    media_id,
                    file_id,
                    t_width,
                    t_height,
                    t_type,
                    t_method,
                    t_len,
                )
            except Exception:
                # Multiple remote media download requests can race (when using
                # multiple media repos), so another worker may have recorded the
                # same thumbnail first. Its row points at the same file, which
                # must therefore be kept. Any other error is re-raised.
                thumbnail_exists = await self.store.get_remote_media_thumbnail(
                    server_name,
                    media_id,
                    t_width,
                    t_height,
                    t_type,
                )
                if not thumbnail_exists:
                    raise
        else:
            await self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

        return output_path, file_info

    async def _apply_media_retention_rules(self) -> None:
        """
        Purge old local and remote media according to the media retention rules
        defined in the homeserver config.
        """
        # Purge remote media
        if self._media_retention_remote_media_lifetime_ms is not None:
            # Calculate a threshold timestamp derived from the configured lifetime. Any
            # media that has not been accessed since this timestamp will be removed.
            remote_media_threshold_timestamp_ms = (
                self.clock.time_msec() - self._media_retention_remote_media_lifetime_ms
            )

            logger.info(
                "Purging remote media last accessed before %s",
                remote_media_threshold_timestamp_ms,
            )

            await self.delete_old_remote_media(
                before_ts=remote_media_threshold_timestamp_ms
            )

        # And now do the same for local media
        if self._media_retention_local_media_lifetime_ms is not None:
            # This works the same as the remote media threshold
            local_media_threshold_timestamp_ms = (
                self.clock.time_msec() - self._media_retention_local_media_lifetime_ms
            )

            logger.info(
                "Purging local media last accessed before %s",
                local_media_threshold_timestamp_ms,
            )

            await self.delete_old_local_media(
                before_ts=local_media_threshold_timestamp_ms,
                keep_profiles=True,
                delete_quarantined_media=False,
                delete_protected_media=False,
            )

    async def delete_old_remote_media(self, before_ts: int) -> dict[str, int]:
        old_media = await self.store.get_remote_media_ids(
            before_ts, include_quarantined_media=False
        )

        deleted = 0

        for origin, media_id, file_id in old_media:
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            # TODO: Should we delete from the backup store
            # Only the local cache is removed. See `_release_sha256` for why
            # storage providers are left unchanged.

            async with self.remote_media_linearizer.queue(key):
                media_info = await self.store.get_cached_remote_media(origin, media_id)
                removed = await self._delete_media_and_thumbnail_files(origin, file_id)
                if not removed:
                    continue

                await self.store.delete_remote_media(origin, media_id)

                # The row is gone, so the shared SHA-256 files can be removed if
                # nothing else references them.
                if media_info and media_info.sha256:
                    await self._release_sha256(origin, media_info.sha256)
                deleted += 1

        return {"deleted": deleted}

    async def delete_local_media_ids(
        self, media_ids: list[str]
    ) -> tuple[list[str], int]:
        """
        Delete the given local or remote media ID from this server

        Args:
            media_id: The media ID to delete.
        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        return await self._remove_local_media_from_disk(media_ids)

    async def delete_old_local_media(
        self,
        before_ts: int,
        size_gt: int = 0,
        keep_profiles: bool = True,
        delete_quarantined_media: bool = False,
        delete_protected_media: bool = False,
    ) -> tuple[list[str], int]:
        """
        Delete local or remote media from this server by size and timestamp. Removes
        media files, any thumbnails and cached URLs.

        Args:
            before_ts: Unix timestamp in ms.
                Files that were last used before this timestamp will be deleted.
            size_gt: Size of the media in bytes. Files that are larger will be deleted.
            keep_profiles: Switch to delete also files that are still used in image data
                (e.g user profile, room avatar). If false these files will be deleted.
            delete_quarantined_media: If True, media marked as quarantined will be deleted.
            delete_protected_media: If True, media marked as protected will be deleted.

        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        old_media = await self.store.get_local_media_ids(
            before_ts,
            size_gt,
            keep_profiles,
            include_quarantined_media=delete_quarantined_media,
            include_protected_media=delete_protected_media,
        )
        return await self._remove_local_media_from_disk(old_media)

    async def _remove_local_media_from_disk(
        self, media_ids: list[str]
    ) -> tuple[list[str], int]:
        """
        Delete local or remote media from this server. Removes media files,
        any thumbnails and cached URLs.

        Args:
            media_ids: List of media_id to delete
        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        # Only the local disk is cleaned up. Storage providers are left unchanged.
        removed_media = []
        for media_id in media_ids:
            logger.info("Deleting media with ID '%s'", media_id)
            media_info = await self.store.get_local_media(media_id)
            removed = await self._delete_media_and_thumbnail_files(None, media_id)
            if not removed:
                continue

            await self.store.delete_remote_media(self.server_name, media_id)

            await self.store.delete_url_cache((media_id,))
            await self.store.delete_url_cache_media((media_id,))

            # Files at the SHA-256 path can be shared with other media of the same
            # content, so they are only removed once the DB row has been deleted
            # and nothing else references them.
            if media_info and media_info.sha256 and not media_info.url_cache:
                await self._release_sha256(None, media_info.sha256)

            removed_media.append(media_id)

        return removed_media, len(removed_media)

    async def _remove_media_id_files_with_sha256(
        self, server_name: str | None, sha256: str
    ) -> None:
        """Remove local media-ID copies of media whose content is now stored at
        its SHA-256 path.

        Part of the gradual migration away from media-ID paths. Media stored
        before deduplication keeps its file at its media-ID path. Once a new
        upload or download creates the SHA-256 file for the same content, every
        row with that SHA-256 reads the SHA-256 path first, so the media-ID copies
        are unused and are removed here.

        Only the original file on local disk is removed. Thumbnails at media-ID
        paths stay, and are still found as a fallback. Storage providers are never
        asked to delete anything. Rows without a SHA-256 are not affected.

        No lock is needed: every affected row already exists and references this
        SHA-256, so a concurrent delete keeps the SHA-256 file.

        Args:
            server_name: The origin of remote media, or None for local media.
            sha256: The SHA-256 of the media.
        """
        identifiers = await self.store.get_media_ids_with_sha256(sha256, server_name)
        for identifier in identifiers:
            # A failure is logged and skipped: the SHA-256 file is already served
            # first, so a leftover media-ID copy is only wasted space.
            await self._remove_media_file(self._media_filepath(server_name, identifier))

    async def _release_sha256(self, server_name: str | None, sha256: str) -> None:
        """Remove the files at a SHA-256 path once the last DB row referencing it
        is deleted. Takes the SHA-256 lock, so the caller must not hold it.

        Storage providers are never asked to delete anything: only the local disk
        is cleaned up. Both the media-ID (or `filesystem_id`) path and the SHA-256
        path, with its thumbnail directory, stay in every provider.

        Operators who want to reclaim provider space must do it out of band, e.g.
        with a bucket lifecycle rule or a cleanup script:
        * A media-ID path can be removed once its row is gone from
          `local_media_repository` (or `remote_media_cache`).
        * A SHA-256 path is shared. Local: remove it only when no row in
          `local_media_repository` with the same `sha256` and `url_cache IS NULL`
          remains. Remote: remove it only when no row in `remote_media_cache` with
          the same `media_origin` and `sha256` remains. Otherwise other media with
          the same content can no longer be served once the local copy is gone,
          and with `enable_local_media_storage: false` the provider copy is the
          only copy.

        Args:
            server_name: The origin of remote media, or None for local media.
            sha256: The SHA-256 of the media.
        """
        # The lock covers only the reference check and the possible file removal.
        # The caller has already deleted the media-ID files and the DB row.
        async with self._lock_sha256_files(server_name, sha256):
            await self._remove_sha256_files_if_unused(server_name, sha256)

    async def _remove_sha256_files_if_unused(
        self, server_name: str | None, sha256: str
    ) -> None:
        """Remove the media file and thumbnails stored under a SHA-256 path, unless
        other media with the same SHA-256 still references them.

        Must be called while holding `_lock_sha256_files` for the same path.

        Args:
            server_name: The origin of remote media, or None for local media.
            sha256: The SHA-256 of the media.
        """
        if await self.store.is_media_sha256_in_use(sha256, server_name):
            logger.debug("SHA-256 %r is in use", sha256)
            # If any of the rows referencing this hash remain, the function returns
            # and the hash file stays.
            return

        # If no row remains, _delete_media_and_thumbnail_files is called again
        # with the SHA-256 as the path identifier.
        await self._delete_media_and_thumbnail_files(server_name, sha256)

    async def _delete_media_and_thumbnail_files(
        self, server_name: str | None, identifier: str
    ) -> bool:
        """Remove a local or remote media file and its thumbnail directory.

        Storage providers are left unchanged. A file that is already gone is
        success. Any other error removing the file is logged so the caller can
        keep the database row.

        Args:
            server_name: The origin of remote media, or None for local media.
            identifier: A media ID, filesystem ID, or SHA-256.

        Returns:
            False when the file could not be removed.
        """

        if not await self._remove_media_file(
            self._media_filepath(server_name, identifier)
        ):
            return False

        await defer_to_thread(
            self.hs.get_reactor(),
            shutil.rmtree,
            self._thumbnail_dirpath(server_name, identifier),
            ignore_errors=True,
        )
        return True

    def _media_filepath(self, server_name: str | None, identifier: str) -> str:
        """The absolute path of an original media file in the local media store.

        Args:
            server_name: The origin of remote media, or None for local media.
            identifier: A media ID, filesystem ID, or SHA-256.
        """
        if server_name:
            return self.filepaths.remote_media_filepath(server_name, identifier)
        return self.filepaths.local_media_filepath(identifier)

    def _thumbnail_dirpath(self, server_name: str | None, identifier: str) -> str:
        """The absolute path of the thumbnail directory of a media file in the
        local media store.

        Args:
            server_name: The origin of remote media, or None for local media.
            identifier: A media ID, filesystem ID, or SHA-256.
        """
        if server_name:
            return self.filepaths.remote_media_thumbnail_dir(server_name, identifier)
        return self.filepaths.local_media_thumbnail_dir(identifier)

    async def _remove_media_file(self, path: str) -> bool:
        """Remove a file from the local media store.

        A file that is already gone is success. Any other error is logged.

        Returns:
            False when the file could not be removed.
        """
        # os.remove blocks until the filesystem returns, and this function runs
        # on the Twisted reactor thread. defer_to_thread moves that wait onto the
        # reactor's thread pool so the worker can keep serving other requests.
        remove_error = await defer_to_thread(self.hs.get_reactor(), _remove_file, path)
        if remove_error is not None and remove_error.errno != errno.ENOENT:
            logger.warning("Failed to remove file: %r: %s", path, remove_error)
            return False
        return True


def _remove_file(path: str) -> OSError | None:
    """Remove `path`. Returns the `OSError` instead of raising it, so the caller
    can decide which errors matter. Should be called from a thread."""
    try:
        os.remove(path)
    except OSError as e:
        return e
    return None
