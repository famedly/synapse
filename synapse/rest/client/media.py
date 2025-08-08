#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2020 The Matrix.org Foundation C.I.C.
# Copyright 2015, 2016 OpenMarket Ltd
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

import logging
import re
from typing import IO, Dict, List, Optional, Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import (
    HttpServer,
    respond_with_json,
    respond_with_json_bytes,
    set_corp_headers,
    set_cors_headers,
)
from synapse.http.servlet import (
    RestServlet,
    parse_bytes_from_args,
    parse_integer,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.media._base import (
    DEFAULT_MAX_TIMEOUT_MS,
    MAXIMUM_ALLOWED_MAX_TIMEOUT_MS,
    respond_404,
)
from synapse.media.media_repository import MediaRepository
from synapse.media.media_storage import MediaStorage, SpamMediaException
from synapse.media.thumbnailer import ThumbnailProvider
from synapse.server import HomeServer
from synapse.util.stringutils import parse_and_validate_server_name

logger = logging.getLogger(__name__)


class PreviewURLServlet(RestServlet):
    """
    Same as `GET /_matrix/media/r0/preview_url`, this endpoint provides a generic preview API
    for URLs which outputs Open Graph (https://ogp.me/) responses (with some Matrix
    specific additions).

    This does have trade-offs compared to other designs:

    * Pros:
      * Simple and flexible; can be used by any clients at any point
    * Cons:
      * If each homeserver provides one of these independently, all the homeservers in a
        room may needlessly DoS the target URI
      * The URL metadata must be stored somewhere, rather than just using Matrix
        itself to store the media.
      * Matrix cannot be used to distribute the metadata between homeservers.
    """

    PATTERNS = [re.compile(r"^/_matrix/client/v1/media/preview_url$")]

    def __init__(
        self,
        hs: "HomeServer",
        media_repo: "MediaRepository",
        media_storage: MediaStorage,
    ):
        super().__init__()

        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.media_repo = media_repo
        self.media_storage = media_storage
        assert self.media_repo.url_previewer is not None
        self.url_previewer = self.media_repo.url_previewer

    async def on_GET(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)
        url = parse_string(request, "url", required=True)
        ts = parse_integer(request, "ts")
        if ts is None:
            ts = self.clock.time_msec()

        og = await self.url_previewer.preview(url, requester.user, ts)
        respond_with_json_bytes(request, 200, og, send_cors=True)


class MediaConfigResource(RestServlet):
    PATTERNS = [re.compile(r"^/_matrix/client/v1/media/config$")]

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        config = hs.config
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()
        self.limits_dict = {"m.upload.size": config.media.max_upload_size}
        self.media_repository_callbacks = hs.get_module_api_callbacks().media_repository

    async def on_GET(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)
        user_specific_config = (
            await self.media_repository_callbacks.get_media_config_for_user(
                requester.user.to_string(),
            )
        )
        response = user_specific_config if user_specific_config else self.limits_dict
        respond_with_json(request, 200, response, send_cors=True)


class ThumbnailResource(RestServlet):
    PATTERNS = [
        re.compile(
            "/_matrix/client/v1/media/thumbnail/(?P<server_name>[^/]*)/(?P<media_id>[^/]*)$"
        )
    ]

    def __init__(
        self,
        hs: "HomeServer",
        media_repo: "MediaRepository",
        media_storage: MediaStorage,
    ):
        super().__init__()

        self.store = hs.get_datastores().main
        self.media_repo = media_repo
        self.media_storage = media_storage
        self.dynamic_thumbnails = hs.config.media.dynamic_thumbnails
        self._is_mine_server_name = hs.is_mine_server_name
        self._server_name = hs.hostname
        self.prevent_media_downloads_from = hs.config.media.prevent_media_downloads_from
        self.thumbnailer = ThumbnailProvider(hs, media_repo, media_storage)
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, server_name: str, media_id: str
    ) -> None:
        # Validate the server name, raising if invalid
        parse_and_validate_server_name(server_name)
        await self.auth.get_user_by_req(request, allow_guest=True)

        set_cors_headers(request)
        set_corp_headers(request)
        width = parse_integer(request, "width", required=True)
        height = parse_integer(request, "height", required=True)
        method = parse_string(request, "method", "scale")
        # TODO Parse the Accept header to get an prioritised list of thumbnail types.
        m_type = "image/png"
        max_timeout_ms = parse_integer(
            request, "timeout_ms", default=DEFAULT_MAX_TIMEOUT_MS
        )
        max_timeout_ms = min(max_timeout_ms, MAXIMUM_ALLOWED_MAX_TIMEOUT_MS)

        if self._is_mine_server_name(server_name):
            if self.dynamic_thumbnails:
                await self.thumbnailer.select_or_generate_local_thumbnail(
                    request,
                    media_id,
                    width,
                    height,
                    method,
                    m_type,
                    max_timeout_ms,
                    False,
                )
            else:
                await self.thumbnailer.respond_local_thumbnail(
                    request,
                    media_id,
                    width,
                    height,
                    method,
                    m_type,
                    max_timeout_ms,
                    False,
                )
            self.media_repo.mark_recently_accessed(None, media_id)
        else:
            # Don't let users download media from configured domains, even if it
            # is already downloaded. This is Trust & Safety tooling to make some
            # media inaccessible to local users.
            # See `prevent_media_downloads_from` config docs for more info.
            if server_name in self.prevent_media_downloads_from:
                respond_404(request)
                return

            ip_address = request.getClientAddress().host
            remote_resp_function = (
                self.thumbnailer.select_or_generate_remote_thumbnail
                if self.dynamic_thumbnails
                else self.thumbnailer.respond_remote_thumbnail
            )
            await remote_resp_function(
                request,
                server_name,
                media_id,
                width,
                height,
                method,
                m_type,
                max_timeout_ms,
                ip_address,
                True,
            )
            self.media_repo.mark_recently_accessed(server_name, media_id)


class DownloadResource(RestServlet):
    PATTERNS = [
        re.compile(
            "/_matrix/client/v1/media/download/(?P<server_name>[^/]*)/(?P<media_id>[^/]*)(/(?P<file_name>[^/]*))?$"
        )
    ]

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()
        self.media_repo = media_repo
        self._is_mine_server_name = hs.is_mine_server_name
        self.auth = hs.get_auth()

    async def on_GET(
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        file_name: Optional[str] = None,
    ) -> None:
        # Validate the server name, raising if invalid
        parse_and_validate_server_name(server_name)

        await self.auth.get_user_by_req(request, allow_guest=True)

        set_cors_headers(request)
        set_corp_headers(request)
        request.setHeader(
            b"Content-Security-Policy",
            b"sandbox;"
            b" default-src 'none';"
            b" script-src 'none';"
            b" plugin-types application/pdf;"
            b" style-src 'unsafe-inline';"
            b" media-src 'self';"
            b" object-src 'self';",
        )
        # Limited non-standard form of CSP for IE11
        request.setHeader(b"X-Content-Security-Policy", b"sandbox;")
        request.setHeader(b"Referrer-Policy", b"no-referrer")
        max_timeout_ms = parse_integer(
            request, "timeout_ms", default=DEFAULT_MAX_TIMEOUT_MS
        )
        max_timeout_ms = min(max_timeout_ms, MAXIMUM_ALLOWED_MAX_TIMEOUT_MS)

        if self._is_mine_server_name(server_name):
            await self.media_repo.get_local_media(
                request, media_id, file_name, max_timeout_ms
            )
        else:
            ip_address = request.getClientAddress().host
            await self.media_repo.get_remote_media(
                request,
                server_name,
                media_id,
                file_name,
                max_timeout_ms,
                ip_address,
                True,
            )


# The name of the lock to use when uploading media.
_UPLOAD_MEDIA_LOCK_NAME = "upload_media"


class BaseUploadServlet(RestServlet):
    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastores().main
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.media.max_upload_size
        self._media_repository_callbacks = (
            hs.get_module_api_callbacks().media_repository
        )

    async def _get_file_metadata(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, Optional[str], str]:
        raw_content_length = request.getHeader("Content-Length")
        if raw_content_length is None:
            raise SynapseError(msg="Request must specify a Content-Length", code=400)
        try:
            content_length = int(raw_content_length)
        except ValueError:
            raise SynapseError(msg="Content-Length value is invalid", code=400)
        if content_length > self.max_upload_size:
            raise SynapseError(
                msg="Upload request body is too large",
                code=413,
                errcode=Codes.TOO_LARGE,
            )
        if not await self._media_repository_callbacks.is_user_allowed_to_upload_media_of_size(
            user_id, content_length
        ):
            raise SynapseError(
                msg="Upload request body is too large",
                code=413,
                errcode=Codes.TOO_LARGE,
            )
        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        upload_name_bytes = parse_bytes_from_args(args, "filename")
        if upload_name_bytes:
            try:
                upload_name: Optional[str] = upload_name_bytes.decode("utf8")
            except UnicodeDecodeError:
                raise SynapseError(
                    msg="Invalid UTF-8 filename parameter: %r" % (upload_name_bytes,),
                    code=400,
                )

        # If the name is falsey (e.g. an empty byte string) ensure it is None.
        else:
            upload_name = None

        headers = request.requestHeaders

        if headers.hasHeader(b"Content-Type"):
            content_type_headers = headers.getRawHeaders(b"Content-Type")
            assert content_type_headers  # for mypy
            media_type = content_type_headers[0].decode("ascii")
        else:
            media_type = "application/octet-stream"

        # if headers.hasHeader(b"Content-Disposition"):
        #     disposition = headers.getRawHeaders(b"Content-Disposition")[0]
        # TODO(markjh): parse content-disposition

        return content_length, upload_name, media_type


class UploadServlet(BaseUploadServlet):
    PATTERNS = [re.compile("/_matrix/client/unstable/org.matrix.msc3911/media/upload$")]

    async def on_POST(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)
        content_length, upload_name, media_type = await self._get_file_metadata(
            request, requester.user.to_string()
        )

        try:
            content: IO = request.content  # type: ignore
            content_uri = await self.media_repo.create_or_update_content(
                media_type, upload_name, content, content_length, requester.user
            )
        except SpamMediaException:
            # For uploading of media we want to respond with a 400, instead of
            # the default 404, as that would just be confusing.
            raise SynapseError(400, "Bad content")

        logger.info("Uploaded content with URI '%s'", content_uri)

        respond_with_json(
            request, 200, {"content_uri": str(content_uri)}, send_cors=True
        )


class AsyncUploadServlet(BaseUploadServlet):
    PATTERNS = [
        re.compile(
            "/_matrix/client/unstable/org.matrix.msc3911/media/upload/(?P<server_name>[^/]*)/(?P<media_id>[^/]*)$"
        )
    ]

    async def on_PUT(
        self, request: SynapseRequest, server_name: str, media_id: str
    ) -> None:
        requester = await self.auth.get_user_by_req(request)

        if server_name != self.server_name:
            raise SynapseError(
                404,
                "Non-local server name specified",
                errcode=Codes.NOT_FOUND,
            )

        lock = await self.store.try_acquire_lock(_UPLOAD_MEDIA_LOCK_NAME, media_id)
        if not lock:
            raise SynapseError(
                409,
                "Media ID cannot be overwritten",
                errcode=Codes.CANNOT_OVERWRITE_MEDIA,
            )

        async with lock:
            await self.media_repo.verify_can_upload(media_id, requester.user)
            content_length, upload_name, media_type = await self._get_file_metadata(
                request, requester.user.to_string()
            )

            try:
                content: IO = request.content  # type: ignore
                await self.media_repo.create_or_update_content(
                    media_type,
                    upload_name,
                    content,
                    content_length,
                    requester.user,
                    media_id=media_id,
                )
            except SpamMediaException:
                # For uploading of media we want to respond with a 400, instead of
                # the default 404, as that would just be confusing.
                raise SynapseError(400, "Bad content")

            logger.info("Uploaded content for media ID %r", media_id)
            respond_with_json(request, 200, {}, send_cors=True)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    media_repo = hs.get_media_repository()
    if hs.config.media.url_preview_enabled:
        PreviewURLServlet(hs, media_repo, media_repo.media_storage).register(
            http_server
        )
    MediaConfigResource(hs).register(http_server)
    ThumbnailResource(hs, media_repo, media_repo.media_storage).register(http_server)
    DownloadResource(hs, media_repo).register(http_server)
