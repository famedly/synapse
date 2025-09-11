import logging
from typing import TYPE_CHECKING, Optional, Tuple, Union

from matrix_common.types.mxc_uri import MXCUri

from synapse.api.errors import (
    SynapseError,
)
from synapse.logging.opentracing import trace
from synapse.storage.databases.main.media_repository import LocalMedia, RemoteMedia
from synapse.types import UserID
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class MediaHandler:
    def __init__(self, hs: "HomeServer"):
        self.server_name = hs.hostname
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.hs = hs
        self._is_mine_server_name = hs.is_mine_server_name
        self.enable_restricted_media = hs.config.experimental.msc3911_enabled
        self.unused_expiration_time = hs.config.media.unused_expiration_time

    @trace
    async def create_media_id(
        self, auth_user: UserID, restricted: bool = False
    ) -> Tuple[str, int]:
        """Create and store a media ID for a local user and return the MXC URI and its
        expiration.

        Args:
            auth_user: The user_id of the uploader
            restricted: If this is to be considered restricted media

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
            restricted=restricted,
        )
        return f"mxc://{self.server_name}/{media_id}", now + self.unused_expiration_time

    async def get_media_info(
        self, mxc_uri: MXCUri
    ) -> Optional[Union[LocalMedia, RemoteMedia]]:
        """Get information about a media item.

        Args:
            mxc_uri: The MXC URI of the media item.

        Returns:
            The media information, or None if not found.
        """
        server_name = mxc_uri.server_name
        media_id = mxc_uri.media_id
        media_info: Union[LocalMedia, RemoteMedia, None] = None
        if self._is_mine_server_name(server_name):
            media_info = await self.store.get_local_media(media_id)
        else:
            media_info = await self.store.get_cached_remote_media(
                mxc_uri.server_name, mxc_uri.media_id
            )
        if not media_info:
            raise SynapseError(404, "Media not found", errcode="M_NOT_FOUND")
        if media_info.quarantined_by:
            raise SynapseError(404, "Media not found", errcode="M_NOT_FOUND")
        return media_info

    async def copy_media(
        self,
        user_id: UserID,
        media_info: Union[Optional[LocalMedia], Optional[RemoteMedia]],
    ) -> Optional[str]:
        """
        Copy media from one location to another.

        Args:
            media_info: The media information to copy.
            mxc_uri: The MXC URI of the media to copy.

        Returns:
            The MXC URI of the copied media, or None if the copy failed.
        """
        try:
            new_mxc_str, _ = await self.create_media_id(user_id, restricted=True)
            mxc_uri = MXCUri.from_str(new_mxc_str)
            if media_info and media_info.media_length and media_info.sha256:
                await self.store.update_local_media(
                    media_id=mxc_uri.media_id,
                    media_type=media_info.media_type,
                    upload_name=media_info.upload_name,
                    media_length=media_info.media_length,
                    user_id=user_id,
                    sha256=media_info.sha256,
                    quarantined_by=None,
                )
            return new_mxc_str

        except Exception as e:
            logger.error("Failed to copy media: %s", e)
            raise SynapseError(500, "Failed to copy media")
