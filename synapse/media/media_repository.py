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
import errno
import logging
import os
import shutil
from http import HTTPStatus
from io import BytesIO
from typing import IO, TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union

import attr
from matrix_common.types.mxc_uri import MXCUri

import twisted.web.http
from twisted.internet.defer import Deferred

from synapse.api.constants import EventTypes, HistoryVisibility, Membership
from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
    UnauthorizedRequestAPICallError,
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
    MediaStorage,
    SHA256TransparentIOReader,
    SHA256TransparentIOWriter,
)
from synapse.media.storage_provider import StorageProviderWrapper
from synapse.media.thumbnailer import Thumbnailer, ThumbnailError
from synapse.media.url_previewer import UrlPreviewer
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.http.media import ReplicationCopyMediaServlet
from synapse.storage.databases.main.media_repository import (
    LocalMedia,
    MediaRestrictions,
    RemoteMedia,
)
from synapse.types import JsonDict, Requester, UserID
from synapse.types.state import StateFilter
from synapse.util import json_decoder
from synapse.util.async_helpers import Linearizer
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import random_string
from synapse.visibility import (
    _HISTORY_VIS_KEY,
    MEMBERSHIP_PRIORITY,
    VISIBILITY_PRIORITY,
    filter_events_for_client,
    get_effective_room_visibility_from_state,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# How often to run the background job to update the "recently accessed"
# attribute of local and remote media.
UPDATE_RECENTLY_ACCESSED_TS = 60 * 1000  # 1 minute
# How often to run the background job to check for local and remote media
# that should be purged according to the configured media retention settings.
MEDIA_RETENTION_CHECK_PERIOD_MS = 60 * 60 * 1000  # 1 hour


class AbstractMediaRepository:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.client = hs.get_federation_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastores().main
        self._is_mine_server_name = hs.is_mine_server_name
        self.enable_media_restriction = self.hs.config.experimental.msc3911_enabled

    @trace
    async def create_media_id_without_expiration(
        self, auth_user: UserID, restricted: bool = False
    ) -> MXCUri:
        """Create and store a media ID for a local user and return the MXC URI and its
        expiration.
        Args:
            auth_user: The user_id of the uploader
            restricted: If this is to be considered restricted media
        Returns:
            A MXC URI of the stored content.
        """
        media_id = random_string(24)
        now = self.clock.time_msec()
        await self.store.store_local_media_id(
            media_id=media_id,
            time_now_ms=now,
            user_id=auth_user,
            restricted=restricted,
        )
        return MXCUri.from_str(f"mxc://{self.server_name}/{media_id}")

    async def get_media_info(self, mxc_uri: MXCUri) -> Union[LocalMedia, RemoteMedia]:
        """Get information about a media item.
        Args:
            mxc_uri: The MXC URI of the media item.
        Returns:
            The media information, or None if not found.
        """
        server_name = mxc_uri.server_name
        media_id = mxc_uri.media_id
        media_info: Optional[Union[LocalMedia, RemoteMedia]]
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

    async def create_or_update_content(
        self,
        media_type: str,
        upload_name: Optional[str],
        content: IO,
        content_length: int,
        auth_user: UserID,
        media_id: Optional[str] = None,
        restricted: bool = False,
    ) -> MXCUri:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def copy_media(
        self, existing_mxc: MXCUri, auth_user: UserID, max_timeout_ms: int
    ) -> MXCUri:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def reached_pending_media_limit(self, auth_user: UserID) -> Tuple[bool, int]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    @trace
    async def _generate_thumbnails(
        self,
        server_name: Optional[str],
        media_id: str,
        file_id: str,
        media_type: str,
        url_cache: bool = False,
    ) -> Optional[dict]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def create_media_id(
        self, auth_user: UserID, restricted: bool = False
    ) -> Tuple[str, int]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def delete_old_remote_media(self, before_ts: int) -> Dict[str, int]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def delete_local_media_ids(
        self, media_ids: List[str]
    ) -> Tuple[List[str], int]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def delete_old_local_media(
        self,
        before_ts: int,
        size_gt: int = 0,
        keep_profiles: bool = True,
        delete_quarantined_media: bool = False,
        delete_protected_media: bool = False,
    ) -> Tuple[List[str], int]:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def get_local_media(
        self,
        request: SynapseRequest,
        media_id: str,
        name: Optional[str],
        max_timeout_ms: int,
        requester: Optional[Requester] = None,
        allow_authenticated: bool = True,
        federation: bool = False,
    ) -> None:
        raise NotImplementedError(
            "Sorry Mario, your MediaRepository related function is in another castle"
        )

    async def validate_media_restriction(
        self,
        request: SynapseRequest,
        media_info: Optional[LocalMedia],
        media_id: Optional[str],
        is_federation: bool = False,
    ) -> Optional[MediaRestrictions]:
        """
        MSC3911: If media is restricted but restriction is empty, the media is in
        pending state and only creator can see it until it is attached to an event. If
        there is a restriction return MediaRestrictions after validation.

        Args:
            request: The incoming request.
            media_info: Optional, the media information.
            media_id: Optional, the media ID to validate.

        Returns:
            MediaRestrictions if there is one set, otherwise raise SynapseError.
        """
        if not media_info and media_id:
            media_info = await self.store.get_local_media(media_id)
        if not media_info:
            return None
        restricted = media_info.restricted
        if not restricted:
            return None
        attachments: Optional[MediaRestrictions] = media_info.attachments
        # for both federation and client endpoints
        if attachments:
            # Only one of event_id or profile_user_id must be set, not both, not neither
            if attachments.event_id is None and attachments.profile_user_id is None:
                raise SynapseError(
                    HTTPStatus.FORBIDDEN,
                    "MediaRestrictions must have exactly one of event_id or profile_user_id set.",
                    errcode=Codes.FORBIDDEN,
                )
            if bool(attachments.event_id) == bool(attachments.profile_user_id):
                raise SynapseError(
                    HTTPStatus.FORBIDDEN,
                    "MediaRestrictions must have exactly one of event_id or profile_user_id set.",
                    errcode=Codes.FORBIDDEN,
                )

        if not attachments and is_federation:
            raise SynapseError(
                HTTPStatus.NOT_FOUND,
                "Not found '%s'" % (request.path.decode(),),
                errcode=Codes.NOT_FOUND,
            )

        if not attachments and not is_federation:
            if (
                isinstance(request.requester, Requester)
                and request.requester.user.to_string() != media_info.user_id
            ):
                raise SynapseError(
                    HTTPStatus.NOT_FOUND,
                    "Not found '%s'" % (request.path.decode(),),
                    errcode=Codes.NOT_FOUND,
                )
            else:
                return None
        return attachments

    async def is_media_visible(
        self, requesting_user: UserID, media_info_object: Union[LocalMedia, RemoteMedia]
    ) -> None:
        """
        Verify that media requested for download should be visible to the user making
        the request
        """

        if not self.enable_media_restriction:
            return

        if not media_info_object.restricted:
            return

        if not media_info_object.attachments:
            # When the media has not been attached yet, only the originating user can
            # see it. But once attachments have been formed, standard other rules apply
            if isinstance(media_info_object, LocalMedia) and (
                requesting_user.to_string() == str(media_info_object.user_id)
            ):
                return

            # It was restricted, but no attachments. Deny
            logger.debug(
                "Media ID ('%s') as requested by '%s' was restricted but had no "
                "attachments",
                media_info_object.media_id,
                requesting_user.to_string(),
            )
            raise UnauthorizedRequestAPICallError(
                f"Media requested ('{media_info_object.media_id}') is restricted"
            )

        attached_event_id = media_info_object.attachments.event_id
        attached_profile_user_id = media_info_object.attachments.profile_user_id

        if attached_event_id:
            event_base = await self.store.get_event(attached_event_id)
            if event_base.is_state():
                # The standard event visibility utility, filter_events_for_client(),
                # does not seem to meet the needs of a good UX when restricting and
                # allowing media. This is a very, very simple version to be used for
                # state events.

                # First we will collect the current membership of the user for the room
                # the relevant event came from. Then we will collect the membership and
                # m.room.history_visibility event at the time of the relevant event.

                # Since it is hard to find a relevant place in which to search back in
                # time to find out if a given room ever had anything other than a leave
                # event, this is the simplest without having to do tablescans

                # Need membership of NOW
                (
                    membership_now,
                    _,
                ) = await self.store.get_local_current_membership_for_user_in_room(
                    requesting_user.to_string(), event_base.room_id
                )

                if not membership_now:
                    membership_now = Membership.LEAVE

                membership_state_key = (EventTypes.Member, requesting_user.to_string())
                types = (_HISTORY_VIS_KEY, membership_state_key)

                # and history visibility and membership of THEN
                state_filter = StateFilter.from_types(types)
                state_handler = self.hs.get_state_handler()

                # State Map to Event IDs
                state_map_to_e_id = await state_handler.compute_state_after_events(
                    event_base.room_id, [attached_event_id], state_filter=state_filter
                )
                # Get the EventBases for those Event IDs
                events = await self.store.get_events(
                    state_map_to_e_id.values(),
                )
                # Sort into mapping of StateMap to EventBases
                state_map = {
                    k: events[v] for k, v in state_map_to_e_id.items() if v in events
                }

                # Don't need to make sure we have an actual StateMap. The defaults
                # applied below handle those occasions. E.g. if it is early in a room
                # at the point of the event we are trying to get visibility on, the
                # state may not exist yet for these filtered events. Like for the
                # membership event that follows room creation.

                visibility = get_effective_room_visibility_from_state(state_map)

                memb_then_evt = state_map.get(membership_state_key)
                membership_then = Membership.LEAVE
                if memb_then_evt:
                    membership_then = memb_then_evt.content.get(
                        "membership", Membership.LEAVE
                    )

                # Have a few numbers ready for comparison below. These resolve to int
                # The index of the visibility present from the event
                visibility_priority = VISIBILITY_PRIORITY.index(visibility)
                membership_priority_now = MEMBERSHIP_PRIORITY.index(membership_now)
                membership_priority_then = MEMBERSHIP_PRIORITY.index(membership_then)

                # These are essentially constants, in that they should not change
                world_readable_index = VISIBILITY_PRIORITY.index(
                    HistoryVisibility.WORLD_READABLE
                )
                shared_visibility_index = VISIBILITY_PRIORITY.index(
                    HistoryVisibility.SHARED
                )
                mem_leave_index = MEMBERSHIP_PRIORITY.index(Membership.LEAVE)

                # I disagree with this. 'Shared' by spec implies that some sort of
                # positive membership event took place, but the stock
                # filter_events_for_client() seems to treat SHARED like WORLD_READABLE,
                # so at least this matches
                if visibility_priority in [
                    world_readable_index,
                    shared_visibility_index,
                ]:
                    # world readable should always be seen
                    return

                # If the room is invite visible, and the user is invited, move on
                if visibility_priority == VISIBILITY_PRIORITY.index(
                    HistoryVisibility.INVITED
                ) and membership_priority_now == MEMBERSHIP_PRIORITY.index(
                    Membership.INVITE
                ):
                    return

                # The visibility of the room is shared or greater, so requires at
                # the minimum a 'knock' level. Make sure the membership of the user
                # is better than leave
                if (
                    visibility_priority >= shared_visibility_index
                    and membership_priority_now < mem_leave_index
                ):
                    return

                # Cover the case that a user has left a room but still should see any
                # media they were allowed to see prior
                # The visibility of the room is shared or greater, so requires at
                # the minimum a 'knock' level. Make sure the membership of the user
                # is better than leave
                if (
                    visibility_priority >= shared_visibility_index
                    and membership_priority_then < mem_leave_index
                ):
                    return

            else:
                storage_controllers = self.hs.get_storage_controllers()
                filtered_events = await filter_events_for_client(
                    storage_controllers,
                    requesting_user.to_string(),
                    [event_base],
                )
                if len(filtered_events) > 0:
                    return

        elif attached_profile_user_id:
            # Can this user see that profile?

            # The error returns here may not be suitable, use the work around below
            # If shared room restricted profile lookups, it will be restricted
            # to users that share rooms
            # await self.profile_handler.check_profile_query_allowed(
            #     restrictions.profile_user_id, requester.user
            # )
            # return

            if self.hs.config.server.limit_profile_requests_to_users_who_share_rooms:
                # First take care of the case where the requesting user IS the creating
                # user. The other function below does not handle this.
                if requesting_user.to_string() == attached_profile_user_id.to_string():
                    return

                # This call returns a set() that contains which of the "other_user_ids"
                # share a room. Since we give it only one, if bool(set()) is True, then they
                # share some room or had at least one invite between them.
                if not await self.store.do_users_share_a_room_joined_or_invited(
                    requesting_user.to_string(),
                    [attached_profile_user_id.to_string()],
                ):
                    logger.debug(
                        "Media ID (%s) as requested by '%s' was restricted by "
                        "profile, but was not allowed(is "
                        "'limit_profile_requests_to_users_who_share_rooms' enabled?)",
                        media_info_object.media_id,
                        requesting_user.to_string(),
                    )

                    raise UnauthorizedRequestAPICallError(
                        f"Media requested ('{media_info_object.media_id}') is restricted"
                    )

            # check these settings:
            # * allow_profile_lookup_over_federation

            # If 'limit_profile_requests_to_users_who_share_rooms' is not enabled, all
            # bets are kinda off
            return

        # It was a third unknown restriction, or otherwise did not pass inspection
        logger.debug(
            "Media ID (%s) as requested by '%s' was restricted, but was not "
            "allowed(media_attachments=%s)",
            media_info_object.media_id,
            requesting_user.to_string(),
            media_info_object.attachments,
        )
        raise UnauthorizedRequestAPICallError(
            f"Media requested ('{media_info_object.media_id}') is restricted"
        )


class MediaRepositoryWorker(AbstractMediaRepository):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        # initialize replication endpoint here
        self.copy_media_client = ReplicationCopyMediaServlet.make_client(hs)

    async def copy_media(
        self, existing_mxc: MXCUri, auth_user: UserID, max_timeout_ms: int
    ) -> MXCUri:
        """
        Call out to the worker responsible for handling media to copy this media object
        """
        result = await self.copy_media_client(
            instance_name=self.hs.config.worker.workers_doing_media_duty[0],
            server_name=existing_mxc.server_name,
            media_id=existing_mxc.media_id,
            user_id=auth_user.to_string(),
            max_timeout_ms=max_timeout_ms,
        )
        return MXCUri.from_str(result["content_uri"])


class MediaRepository(AbstractMediaRepository):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.max_upload_size = hs.config.media.max_upload_size
        self.max_image_pixels = hs.config.media.max_image_pixels
        self.unused_expiration_time = hs.config.media.unused_expiration_time
        self.max_pending_media_uploads = hs.config.media.max_pending_media_uploads

        Thumbnailer.set_limits(self.max_image_pixels)

        self.primary_base_path: str = hs.config.media.media_store_path
        self.filepaths: MediaFilePaths = MediaFilePaths(self.primary_base_path)

        self.dynamic_thumbnails = hs.config.media.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.media.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote")

        self.recently_accessed_remotes: Set[Tuple[str, str]] = set()
        self.recently_accessed_locals: Set[str] = set()

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

        self.media_storage: MediaStorage = MediaStorage(
            self.hs, self.primary_base_path, self.filepaths, storage_providers
        )

        self.clock.looping_call(
            self._start_update_recently_accessed, UPDATE_RECENTLY_ACCESSED_TS
        )

        # Media retention configuration options
        self._media_retention_local_media_lifetime_ms = (
            hs.config.media.media_retention_local_media_lifetime_ms
        )
        self._media_retention_remote_media_lifetime_ms = (
            hs.config.media.media_retention_remote_media_lifetime_ms
        )

        self.enable_local_media_storage_deduplication = (
            hs.config.media.enable_local_media_storage_deduplication
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
                MEDIA_RETENTION_CHECK_PERIOD_MS,
            )

        if hs.config.media.url_preview_enabled:
            self.url_previewer: Optional[UrlPreviewer] = UrlPreviewer(
                hs, self, self.media_storage
            )
        else:
            self.url_previewer = None

        # We get the media upload limits and sort them in descending order of
        # time period, so that we can apply some optimizations.
        self.media_upload_limits = hs.config.media.media_upload_limits
        self.media_upload_limits.sort(
            key=lambda limit: limit.time_period_ms, reverse=True
        )

    def _start_update_recently_accessed(self) -> Deferred:
        return run_as_background_process(
            "update_recently_accessed_media", self._update_recently_accessed
        )

    def _start_apply_media_retention_rules(self) -> Deferred:
        return run_as_background_process(
            "apply_media_retention_rules", self._apply_media_retention_rules
        )

    async def _update_recently_accessed(self) -> None:
        remote_media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        local_media = self.recently_accessed_locals
        self.recently_accessed_locals = set()

        await self.store.update_cached_last_access_time(
            local_media, remote_media, self.clock.time_msec()
        )

    def mark_recently_accessed(self, server_name: Optional[str], media_id: str) -> None:
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

    @trace
    async def reached_pending_media_limit(self, auth_user: UserID) -> Tuple[bool, int]:
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

    def check_file_path_exists_by_sha256(self, sha256: str) -> bool:
        if not self.enable_local_media_storage_deduplication:
            logger.debug("sha256 path is not enabled.")
        return os.path.exists(self.filepaths.filepath_sha(sha256))

    @trace
    async def create_or_update_content(
        self,
        media_type: str,
        upload_name: Optional[str],
        content: IO,
        content_length: int,
        auth_user: UserID,
        media_id: Optional[str] = None,
        restricted: bool = False,
        sha256: Optional[str] = None,
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
            restricted: Boolean for if the media is restricted per msc3911

        Returns:
            The mxc url of the stored content
        """

        is_new_media = media_id is None
        if media_id is None:
            media_id = random_string(24)

        file_info = FileInfo(server_name=None, file_id=media_id)
        sha256reader = SHA256TransparentIOReader(content)
        # This implements all of IO as it has a passthrough
        fname = await self.media_storage.store_file(sha256reader.wrap(), file_info)
        sha256 = sha256reader.hexdigest()
        should_quarantine = await self.store.get_is_hash_quarantined(sha256)

        logger.info("Stored local media in file %r", fname)

        if should_quarantine:
            logger.warning(
                "Media has been automatically quarantined as it matched existing quarantined media"
            )

        # If we enabled sha256 paths, we create a new file with sha256 path, and delete
        # the original media_id path.
        if self.enable_local_media_storage_deduplication:
            if not self.check_file_path_exists_by_sha256(sha256):
                file_info = FileInfo(server_name=None, file_id=media_id, sha256=sha256)
                sha256_fname = await self.media_storage.store_file(content, file_info)
                logger.info("Stored media in file %r", sha256_fname)
            else:
                logger.info("File already exists in sha256 path.")
            os.remove(fname)

        # Check that the user has not exceeded any of the media upload limits.

        # This is the total size of media uploaded by the user in the last
        # `time_period_ms` milliseconds, or None if we haven't checked yet.
        uploaded_media_size: Optional[int] = None

        # Note: the media upload limits are sorted so larger time periods are
        # first.
        for limit in self.media_upload_limits:
            # We only need to check the amount of media uploaded by the user in
            # this latest (smaller) time period if the amount of media uploaded
            # in a previous (larger) time period is above the limit.
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
                raise SynapseError(
                    400, "Media upload limit exceeded", Codes.RESOURCE_LIMIT_EXCEEDED
                )

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
                restricted=restricted,
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

        try:
            await self._generate_thumbnails(
                server_name=None,
                media_id=media_id,
                file_id=sha256
                if self.enable_local_media_storage_deduplication
                else media_id,
                media_type=media_type,
                sha256=sha256
                if self.enable_local_media_storage_deduplication
                else None,
            )
        except Exception as e:
            logger.info("Failed to generate thumbnails: %s", e)

        return MXCUri(self.server_name, media_id)

    async def copy_media(
        self, existing_mxc: MXCUri, auth_user: UserID, max_timeout_ms: int
    ) -> MXCUri:
        """
        Copy an existing piece of media into a new file with new LocalMedia

        Args:
            existing_mxc: The existing media information
            auth_user: The UserID of the user making the request
            max_timeout_ms: The millisecond timeout for retrieving existing media info
        """

        old_media_info = await self.get_media_info(existing_mxc)
        if isinstance(old_media_info, RemoteMedia):
            file_info = FileInfo(
                server_name=old_media_info.media_origin,
                file_id=old_media_info.filesystem_id,
                sha256=old_media_info.sha256
                if self.enable_local_media_storage_deduplication
                and old_media_info.sha256
                else None,
            )
        else:
            file_info = FileInfo(
                server_name=None,
                file_id=old_media_info.media_id,
                sha256=old_media_info.sha256
                if self.enable_local_media_storage_deduplication
                and old_media_info.sha256
                else None,
            )

        # This will ensure that if there is another storage provider containing our old
        # media, it will be in our local cache before the copy takes place.
        # Conveniently, it also gives us the local path of where the file lives.
        local_path = await self.media_storage.ensure_media_is_in_local_cache(file_info)

        assert old_media_info.media_length is not None

        # It may end up being that this needs to be pushed down into the MediaStorage
        # class. It needs abstraction badly, but that is beyond me at the moment.
        io_object = open(local_path, "rb")

        # Let existing methods handle creating the new file for us. By not passing a
        # media id, one will be created.
        new_mxc_uri = await self.create_or_update_content(
            old_media_info.media_type,
            old_media_info.upload_name,
            io_object,
            old_media_info.media_length,
            auth_user,
            restricted=True,
            sha256=old_media_info.sha256,
        )
        # I could not find a place this was close()'d explicitly, but this felt prudent
        io_object.close()

        return new_mxc_uri

    def respond_not_yet_uploaded(self, request: SynapseRequest) -> None:
        respond_with_json(
            request,
            504,
            cs_error("Media has not been uploaded yet", code=Codes.NOT_YET_UPLOADED),
            send_cors=True,
        )

    async def get_local_media_info(
        self, request: SynapseRequest, media_id: str, max_timeout_ms: int
    ) -> Optional[LocalMedia]:
        """Gets the info dictionary for given local media ID. If the media has
        not been uploaded yet, this function will wait up to ``max_timeout_ms``
        milliseconds for the media to be uploaded.

        Args:
            request: The incoming request.
            media_id: The media ID of the content. (This is the same as
                the file_id for local content.)
            max_timeout_ms: the maximum number of milliseconds to wait for the
                media to be uploaded.

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

            if media_info.quarantined_by:
                logger.info("Media %s is quarantined", media_id)
                respond_404(request)
                return None

            # The file has been uploaded, so stop looping
            if media_info.media_length is not None:
                if isinstance(request.requester, Requester):
                    await self.is_media_visible(request.requester.user, media_info)
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

            await self.clock.sleep(0.5)

        logger.info("Media %s has not yet been uploaded", media_id)
        self.respond_not_yet_uploaded(request)
        return None

    async def get_local_media(
        self,
        request: SynapseRequest,
        media_id: str,
        name: Optional[str],
        max_timeout_ms: int,
        requester: Optional[Requester] = None,
        allow_authenticated: bool = True,
        federation: bool = False,
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
            requester: The user making the request, to verify restricted media. Only
                used for local users, not over federation
            allow_authenticated: whether media marked as authenticated may be served to this request
            federation: whether the local media being fetched is for a federation request

        Returns:
            Resolves once a response has successfully been written to request
        """
        media_info = await self.get_local_media_info(request, media_id, max_timeout_ms)
        if not media_info:
            return

        if self.hs.config.media.enable_authenticated_media and not allow_authenticated:
            if media_info.authenticated:
                raise NotFoundError()

        restrictions = None
        # if MSC3911 is enabled, check visibility of the media for the user and retrieve
        # any restrictions
        if self.enable_media_restriction:
            if requester is not None:
                # Only check media visibility if this is for a local request. This will
                # raise directly back to the client if not visible
                await self.is_media_visible(requester.user, media_info)
            restrictions = await self.validate_media_restriction(
                request, media_info, None, federation
            )
        restrictions_json = restrictions.to_dict() if restrictions else {}

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
            None,
            media_id,
            url_cache=bool(url_cache),
            sha256=media_info.sha256
            if self.enable_local_media_storage_deduplication
            else None,
        )

        responder = await self.media_storage.fetch_media(file_info)
        if federation:
            await respond_with_multipart_responder(
                self.clock,
                request,
                responder,
                media_type,
                media_length,
                upload_name,
                restrictions_json,
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
        name: Optional[str],
        max_timeout_ms: int,
        ip_address: str,
        use_federation_endpoint: bool,
        requester: Optional[Requester] = None,
        allow_authenticated: bool = True,
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
            requester: The user making the request, to verify restricted media. Only
                used for local users, not over federation
            allow_authenticated: whether media marked as authenticated may be served to this
                request

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
                requester,
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
        requester: Optional[Requester] = None,
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
            requester: The user making the request, to verify restricted media. Only
                used for local users, not over federation

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
                requester,
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
        requester: Optional[Requester] = None,
    ) -> Tuple[Optional[Responder], RemoteMedia]:
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
            allow_authenticated:
            requester: The user making the request, to verify restricted media. Only
                used for local users, not over federation

        Returns:
            A tuple of responder and the media info of the file.
        """
        media_info = await self.store.get_cached_remote_media(server_name, media_id)

        if self.hs.config.media.enable_authenticated_media and not allow_authenticated:
            # if it isn't cached then don't fetch it or if it's authenticated then don't serve it
            if not media_info or media_info.authenticated:
                raise NotFoundError()

        # If we have an entry in the DB, try and look for it
        if media_info:
            # if MSC3911 is enabled, check visibility of the media for the user. This
            # check exists twice in this function, once up here for when it already
            # exists in the local database and again further down for after it was
            # retrieved from the remote.
            if self.enable_media_restriction and requester is not None:
                # This will raise directly back to the client if not visible
                await self.is_media_visible(requester.user, media_info)

            # file_id is the ID we use to track the file locally. If we've already
            # seen the file then reuse the existing ID, otherwise generate a new
            # one.
            file_id = media_info.filesystem_id
            file_info = FileInfo(
                server_name,
                file_id,
                sha256=media_info.sha256
                if self.enable_local_media_storage_deduplication and media_info.sha256
                else None,
            )

            if media_info.quarantined_by:
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
            if not use_federation_endpoint:
                media_info = await self._download_remote_file(
                    server_name,
                    media_id,
                    max_timeout_ms,
                    download_ratelimiter,
                    ip_address,
                )
            else:
                media_info = await self._federation_download_remote_file(
                    server_name,
                    media_id,
                    max_timeout_ms,
                    download_ratelimiter,
                    ip_address,
                )

        except SynapseError:
            raise
        except Exception as e:
            # An exception may be because we downloaded media in another
            # process, so let's check if we magically have the media.
            media_info = await self.store.get_cached_remote_media(server_name, media_id)
            if not media_info:
                raise e

        # if MSC3911 is enabled, check visibility of the media for the user.
        # Restricted media requires authentication to be enabled
        if (
            self.hs.config.media.enable_authenticated_media
            and self.enable_media_restriction
            and requester is not None
        ):
            # This will raise directly back to the client if not visible
            await self.is_media_visible(requester.user, media_info)

        file_id = media_info.filesystem_id

        if not media_info.media_type:
            media_info = attr.evolve(media_info, media_type="application/octet-stream")

        file_info = FileInfo(
            server_name,
            media_info.sha256
            if self.enable_local_media_storage_deduplication and media_info.sha256
            else file_id,
            sha256=media_info.sha256
            if self.enable_local_media_storage_deduplication and media_info.sha256
            else None,
        )
        # We generate thumbnails even if another process downloaded the media
        # as a) it's conceivable that the other download request dies before it
        # generates thumbnails, but mainly b) we want to be sure the thumbnails
        # have finished being generated before responding to the client,
        # otherwise they'll request thumbnails and get a 404 if they're not
        # ready yet.
        if self.enable_local_media_storage_deduplication:
            assert media_info.sha256 is not None
            await self._generate_thumbnails(
                server_name=server_name,
                media_id=media_id,
                file_id=media_info.sha256,  # Passing over sha256 for file_id if sha256 path is enabled.
                media_type=media_info.media_type,
                sha256=media_info.sha256,
            )
        else:
            await self._generate_thumbnails(
                server_name, media_id, file_id, media_info.media_type
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
    ) -> RemoteMedia:
        """Attempt to download the remote file from the given server name,
        using the given file_id as the local id.

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

        Returns:
            The media info of the file.
        """

        file_id = random_string(24)

        file_info = FileInfo(server_name=server_name, file_id=file_id)

        async with self.media_storage.store_into_file(file_info) as (f, fname):
            sha256writer = SHA256TransparentIOWriter(f)
            try:
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

            # Multiple remote media download requests can race (when using
            # multiple media repos), so this may throw a violation constraint
            # exception. If it does we'll delete the newly downloaded file from
            # disk (as we're in the ctx manager).
            #
            # However: we've already called `finish()` so we may have also
            # written to the storage providers. This is preferable to the
            # alternative where we call `finish()` *after* this, where we could
            # end up having an entry in the DB but fail to write the files to
            # the storage providers.
            await self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=time_now_ms,
                upload_name=upload_name,
                media_length=length,
                filesystem_id=sha256
                if self.enable_local_media_storage_deduplication
                else file_id,
                sha256=sha256,
            )

        logger.info("Stored remote media in file %r", fname)

        if self.hs.config.media.enable_authenticated_media:
            authenticated = True
        else:
            authenticated = False

        # If sha256 paths are enabled, rename the file to sha256 path and delete the original media_id path.
        if self.enable_local_media_storage_deduplication:
            rel_path = self.filepaths.filepath_sha(sha256)
            abs_path = os.path.join(self.hs.config.media.media_store_path, rel_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            os.rename(fname, abs_path)
            os.remove(fname)

        return RemoteMedia(
            media_origin=server_name,
            media_id=media_id,
            media_type=media_type,
            media_length=length,
            upload_name=upload_name,
            created_ts=time_now_ms,
            filesystem_id=sha256
            if self.enable_local_media_storage_deduplication
            else file_id,
            last_access_ts=time_now_ms,
            quarantined_by=None,
            authenticated=authenticated,
            sha256=sha256,
            # The "pre-msc3916" method for downloading over federation, restricted
            # will always be false and attachments will always be None here
            restricted=False,
            attachments=None,
        )

    async def _federation_download_remote_file(
        self,
        server_name: str,
        media_id: str,
        max_timeout_ms: int,
        download_ratelimiter: Ratelimiter,
        ip_address: str,
    ) -> RemoteMedia:
        """Attempt to download the remote file from the given server name.
        Uses the given file_id as the local id and downloads the file over the federation
        v1 download endpoint

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

        Returns:
            The media info of the file.
        """

        file_id = random_string(24)

        file_info = FileInfo(server_name=server_name, file_id=file_id)

        async with self.media_storage.store_into_file(file_info) as (f, fname):
            sha256writer = SHA256TransparentIOWriter(f)
            try:
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
                # if we had to fall back to the _matrix/media endpoint it will only return
                # the headers and length, check the length of the tuple before unpacking
                attachment_dict: JsonDict
                if len(res) == 3:
                    length, headers, json_bytes = res
                    if json_bytes:
                        attachment_dict = json_decoder.decode(json_bytes.decode())
                else:
                    length, headers = res
                    # This is set to an empty {} just as it is responded when media is
                    # not restricted, thus maintaining backwards compatibility
                    attachment_dict = {}
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

            # Multiple remote media download requests can race (when using
            # multiple media repos), so this may throw a violation constraint
            # exception. If it does we'll delete the newly downloaded file from
            # disk (as we're in the ctx manager).
            #
            # However: we've already called `finish()` so we may have also
            # written to the storage providers. This is preferable to the
            # alternative where we call `finish()` *after* this, where we could
            # end up having an entry in the DB but fail to write the files to
            # the storage providers.

            # The unstable prefix on 'restrictions' will be here. Do not save that to
            # the database, but filter it out. This is the companion to it's opposite in
            # MediaRestrictions.to_dict() which adds it while unstable.
            if "org.matrix.msc3911.restrictions" in attachment_dict:
                restrictions_values = attachment_dict.pop(
                    "org.matrix.msc3911.restrictions"
                )
                attachment_dict["restrictions"] = restrictions_values

            # This can come in as 'falsey'(like '{}' or 'b""') so if this happens it has
            # no restrictions. If it was restricted remotely, but had no attachments,
            # then it should not have come across federation
            restricted = True if "restrictions" in attachment_dict else False

            await self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=time_now_ms,
                upload_name=upload_name,
                media_length=length,
                filesystem_id=sha256
                if self.enable_local_media_storage_deduplication
                else file_id,
                sha256=sha256,
                restricted=restricted,
            )
            # TODO: Decide about raising here? It will delete the media from the
            #  disk but will not remove the restricted flag from the remote media
            #  entry that just got wrote. Is this important? According to the comment
            #  blocks above the last statement, it could raise a constraint violation
            #  which would block this from being called. But if it is racing, we may have
            #  been here before. Should this be gracefully handled(and basically ignored)?
            # To keep the 'media_attachments' table smaller, unrestricted media does not
            # have a row, only the restricted column for both local and remote media
            attachments: Optional[MediaRestrictions] = None
            if attachment_dict:
                attachments = MediaRestrictions(**attachment_dict["restrictions"])
                await self.store.set_media_restrictions(
                    server_name, media_id, attachment_dict
                )

        logger.debug("Stored remote media in file %r", fname)

        if self.hs.config.media.enable_authenticated_media:
            authenticated = True
        else:
            authenticated = False

        # If sha256 paths are enabled, rename the file to sha256 path and delete the original media_id path.
        if self.enable_local_media_storage_deduplication:
            rel_path = self.filepaths.filepath_sha(sha256)
            abs_path = os.path.join(self.hs.config.media.media_store_path, rel_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            os.rename(fname, abs_path)
            os.remove(fname)

        return RemoteMedia(
            media_origin=server_name,
            media_id=media_id,
            media_type=media_type,
            media_length=length,
            upload_name=upload_name,
            created_ts=time_now_ms,
            filesystem_id=sha256
            if self.enable_local_media_storage_deduplication
            else file_id,
            last_access_ts=time_now_ms,
            quarantined_by=None,
            authenticated=authenticated,
            sha256=sha256,
            restricted=restricted,
            attachments=attachments,
        )

    def _get_thumbnail_requirements(
        self, media_type: str
    ) -> Tuple[ThumbnailRequirement, ...]:
        scpos = media_type.find(";")
        if scpos > 0:
            media_type = media_type[:scpos]
        return self.thumbnail_requirements.get(media_type, ())

    def _generate_thumbnail(
        self,
        thumbnailer: Thumbnailer,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
    ) -> Optional[BytesIO]:
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

        if t_method == "crop":
            return thumbnailer.crop(t_width, t_height, t_type)
        elif t_method == "scale":
            t_width, t_height = thumbnailer.aspect(t_width, t_height)
            t_width = min(m_width, t_width)
            t_height = min(m_height, t_height)
            return thumbnailer.scale(t_width, t_height, t_type)

        return None

    async def generate_local_exact_thumbnail(
        self,
        media_id: str,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        url_cache: bool,
        sha256: Optional[str] = None,
    ) -> Optional[Tuple[str, FileInfo]]:
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(
                None,
                media_id,
                url_cache=url_cache,
                sha256=sha256
                if self.enable_local_media_storage_deduplication and sha256
                else None,
            )
        )

        try:
            thumbnailer = Thumbnailer(input_path)
        except ThumbnailError as e:
            logger.warning(
                "Unable to generate a thumbnail for local media %s using a method of %s and type of %s: %s",
                media_id,
                t_method,
                t_type,
                e,
            )
            return None

        with thumbnailer:
            t_byte_source = await defer_to_thread(
                self.hs.get_reactor(),
                self._generate_thumbnail,
                thumbnailer,
                t_width,
                t_height,
                t_method,
                t_type,
            )

        if t_byte_source:
            try:
                file_info = FileInfo(
                    server_name=None,
                    file_id=sha256
                    if self.enable_local_media_storage_deduplication and sha256
                    else media_id,
                    url_cache=url_cache,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                        length=t_byte_source.tell(),
                    ),
                    sha256=sha256
                    if self.enable_local_media_storage_deduplication and sha256
                    else None,
                )

                output_path = await self.media_storage.store_file(
                    t_byte_source, file_info
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

            await self.store.store_local_thumbnail(
                media_id,
                t_width,
                t_height,
                t_type,
                t_method,
                t_len,
            )

            return output_path, file_info

        # Could not generate thumbnail.
        return None

    async def generate_remote_exact_thumbnail(
        self,
        server_name: str,
        file_id: str,
        media_id: str,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        sha256: Optional[str] = None,
    ) -> Optional[str]:
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(
                server_name,
                file_id,
                sha256=sha256
                if self.enable_local_media_storage_deduplication and sha256
                else None,
            )
        )

        try:
            thumbnailer = Thumbnailer(input_path)
        except ThumbnailError as e:
            logger.warning(
                "Unable to generate a thumbnail for remote media %s from %s using a method of %s and type of %s: %s",
                media_id,
                server_name,
                t_method,
                t_type,
                e,
            )
            return None

        with thumbnailer:
            t_byte_source = await defer_to_thread(
                self.hs.get_reactor(),
                self._generate_thumbnail,
                thumbnailer,
                t_width,
                t_height,
                t_method,
                t_type,
            )

        if t_byte_source:
            try:
                file_info = FileInfo(
                    server_name=server_name,
                    file_id=file_id,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                        length=t_byte_source.tell(),
                    ),
                    sha256=sha256
                    if self.enable_local_media_storage_deduplication and sha256
                    else None,
                )

                output_path = await self.media_storage.store_file(
                    t_byte_source, file_info
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

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

            return output_path

        # Could not generate thumbnail.
        return None

    @trace
    async def _generate_thumbnails(
        self,
        server_name: Optional[str],
        media_id: str,
        file_id: str,
        media_type: str,
        url_cache: bool = False,
        sha256: Optional[str] = None,
    ) -> Optional[dict]:
        """Generate and store thumbnails for an image.

        Args:
            server_name: The server name if remote media, else None if local
            media_id: The media ID of the content. (This is the same as
                the file_id for local content)
            file_id: Local file ID. If sha256 path is enabled, this will be the sha256 of the media.
            media_type: The content type of the file
            url_cache: If we are thumbnailing images downloaded for the URL cache,
                used exclusively by the url previewer
            sha256: The sha256 of the media. This will be used as the path, if sha256 path is enabled.

        Returns:
            Dict with "width" and "height" keys of original image or None if the
            media cannot be thumbnailed.
        """
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return None

        file_info = FileInfo(
            server_name,
            file_id,  # This will be the sha256 if sha256 path is enabled. Otherwise, it will be the file_id.
            url_cache=url_cache,
            sha256=sha256
            if self.enable_local_media_storage_deduplication and sha256
            else None,
        )
        input_path = await self.media_storage.ensure_media_is_in_local_cache(file_info)

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
                m_width, m_height = await defer_to_thread(
                    self.hs.get_reactor(), thumbnailer.transpose
                )

            # We deduplicate the thumbnail sizes by ignoring the cropped versions if
            # they have the same dimensions of a scaled one.
            thumbnails: Dict[Tuple[int, int, str], str] = {}
            for requirement in requirements:
                if requirement.method == "crop":
                    thumbnails.setdefault(
                        (requirement.width, requirement.height, requirement.media_type),
                        requirement.method,
                    )
                elif requirement.method == "scale":
                    t_width, t_height = thumbnailer.aspect(
                        requirement.width, requirement.height
                    )
                    t_width = min(m_width, t_width)
                    t_height = min(m_height, t_height)
                    thumbnails[(t_width, t_height, requirement.media_type)] = (
                        requirement.method
                    )

            # Now we generate the thumbnails for each dimension, store it
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

                if not t_byte_source:
                    continue

                file_info = FileInfo(
                    server_name=server_name,
                    file_id=sha256
                    if self.enable_local_media_storage_deduplication and sha256
                    else file_id,  # Saving the thumbnail with sha256 path if sha256 path is enabled.
                    url_cache=url_cache,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                        length=t_byte_source.tell(),
                    ),
                    sha256=sha256
                    if self.enable_local_media_storage_deduplication and sha256
                    else None,
                )

                async with self.media_storage.store_into_file(file_info) as (f, fname):
                    try:
                        await self.media_storage.write_to_file(t_byte_source, f)
                    finally:
                        t_byte_source.close()

                    # We flush and close the file to ensure that the bytes have
                    # been written before getting the size.
                    f.flush()
                    f.close()

                    t_len = os.path.getsize(fname)

                    # Write to database
                    if server_name:
                        # Multiple remote media download requests can race (when
                        # using multiple media repos), so this may throw a violation
                        # constraint exception. If it does we'll delete the newly
                        # generated thumbnail from disk (as we're in the ctx
                        # manager).
                        #
                        # However: we've already called `finish()` so we may have
                        # also written to the storage providers. This is preferable
                        # to the alternative where we call `finish()` *after* this,
                        # where we could end up having an entry in the DB but fail
                        # to write the files to the storage providers.
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
                        except Exception as e:
                            thumbnail_exists = (
                                await self.store.get_remote_media_thumbnail(
                                    server_name,
                                    media_id,
                                    t_width,
                                    t_height,
                                    t_type,
                                )
                            )
                            if not thumbnail_exists:
                                raise e
                    else:
                        await self.store.store_local_thumbnail(
                            media_id, t_width, t_height, t_type, t_method, t_len
                        )

        return {"width": m_width, "height": m_height}

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

    async def delete_old_remote_media(self, before_ts: int) -> Dict[str, int]:
        old_media = await self.store.get_remote_media_ids(
            before_ts, include_quarantined_media=False
        )

        deleted = 0

        for origin, media_id, file_id in old_media:
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            # TODO: Should we delete from the backup store

            async with self.remote_media_linearizer.queue(key):
                full_path = self.filepaths.remote_media_filepath(origin, file_id)
                try:
                    os.remove(full_path)
                except OSError as e:
                    logger.warning("Failed to remove file: %r", full_path)
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        continue

                thumbnail_dir = self.filepaths.remote_media_thumbnail_dir(
                    origin, file_id
                )
                shutil.rmtree(thumbnail_dir, ignore_errors=True)

                await self.store.delete_remote_media(origin, media_id)
                deleted += 1

        return {"deleted": deleted}

    async def delete_local_media_ids(
        self, media_ids: List[str]
    ) -> Tuple[List[str], int]:
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
    ) -> Tuple[List[str], int]:
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
        self, media_ids: List[str]
    ) -> Tuple[List[str], int]:
        """
        Delete local or remote media from this server. Removes media files,
        any thumbnails and cached URLs.

        Args:
            media_ids: List of media_id to delete
        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        removed_media = []
        for media_id in media_ids:
            logger.info("Deleting media with ID '%s'", media_id)
            sha256 = await self.store.get_sha_by_media_id(media_id, None)
            paths = [
                self.filepaths.local_media_filepath(media_id),
                self.filepaths.filepath_sha(sha256),
            ]
            for path in paths:
                try:
                    os.remove(path)
                except OSError as e:
                    logger.warning("Failed to remove file: %r: %s", path, e)
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        continue

            thumbnail_dir = self.filepaths.local_media_thumbnail_dir(media_id)
            thumbnail_dir_sha = self.filepaths.thumbnail_sha_dir(sha256)
            shutil.rmtree(thumbnail_dir, ignore_errors=True)
            shutil.rmtree(thumbnail_dir_sha, ignore_errors=True)

            await self.store.delete_remote_media(self.server_name, media_id)

            await self.store.delete_url_cache((media_id,))
            await self.store.delete_url_cache_media((media_id,))

            removed_media.append(media_id)

        return removed_media, len(removed_media)
