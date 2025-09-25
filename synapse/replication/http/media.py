#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
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

import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from matrix_common.types.mxc_uri import MXCUri

from twisted.web.server import Request

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationCopyMediaServlet(ReplicationEndpoint):
    """Request the MediaRepository to make a copy of a piece of media.

    Request format:

        POST /_synapse/replication/copy_media/:server_name/:media_id

        {
            "user_id": UserID.to_string(),
            "max_timeout_ms": int of how long to wait
        }

    """

    NAME = "copy_media"
    PATH_ARGS = ("server_name", "media_id")

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.media_repo = hs.get_media_repository()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        server_name: str,
        media_id: str,
        user_id: str,
        max_timeout_ms: int,
    ) -> JsonDict:
        """
        Args:
            server_name: The server_name that originated the media.
            media_id: The individualized media id for the origin media.
        """
        return {"user_id": user_id, "max_timeout_ms": max_timeout_ms}

    async def _handle_request(  # type: ignore[override]
        self,
        request: Request,
        content: JsonDict,
        server_name: str,
        media_id: str,
    ) -> Tuple[int, JsonDict]:
        user_id = UserID.from_string(content["user_id"])
        max_timeout_ms = content["max_timeout_ms"]
        try:
            mxc_uri = MXCUri(server_name=server_name, media_id=media_id)
        except ValueError:
            # TODO: Make sure the codes here are proper
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "MXC as provided was not formatted correctly",
                Codes.INVALID_PARAM,
            )
        copied_mxc_uri = await self.media_repo.copy_media(
            mxc_uri, user_id, max_timeout_ms=max_timeout_ms
        )
        return 200, {"content_uri": str(copied_mxc_uri)}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationCopyMediaServlet(hs).register(http_server)
