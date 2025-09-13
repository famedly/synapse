#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
import logging
import os
import time
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple

from matrix_common.types.mxc_uri import MXCUri

from twisted.internet.protocol import Factory
from twisted.test.proto_helpers import MemoryReactor
from twisted.web.http import HTTPChannel
from twisted.web.server import Request

from synapse.api.constants import EventTypes, HistoryVisibility
from synapse.media._base import FileInfo
from synapse.media.media_repository import MediaRepository
from synapse.rest import admin
from synapse.rest.client import login, media, room
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util import Clock

from tests.http import (
    TestServerTLSConnectionFactory,
    get_test_ca_cert_file,
    wrap_server_factory_for_tls,
)
from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.server import FakeChannel, FakeTransport, make_request
from tests.test_utils import SMALL_PNG, SMALL_PNG_SHA256
from tests.unittest import override_config

logger = logging.getLogger(__name__)

test_server_connection_factory: Optional[TestServerTLSConnectionFactory] = None


class MediaRepoShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks running multiple media repos work correctly."""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = self.register_user("user", "pass")
        self.access_token = self.login("user", "pass")

        self.reactor.lookups["example.com"] = "1.2.3.4"

    def default_config(self) -> dict:
        conf = super().default_config()
        conf["federation_custom_ca_list"] = [get_test_ca_cert_file()]
        return conf

    def make_worker_hs(
        self, worker_app: str, extra_config: Optional[dict] = None, **kwargs: Any
    ) -> HomeServer:
        worker_hs = super().make_worker_hs(worker_app, extra_config, **kwargs)
        # Force the media paths onto the replication resource.
        worker_hs.get_media_repository_resource().register_servlets(
            self._hs_to_site[worker_hs].resource, worker_hs
        )
        return worker_hs

    def _get_media_req(
        self, hs: HomeServer, target: str, media_id: str
    ) -> Tuple[FakeChannel, Request]:
        """Request some remote media from the given HS by calling the download
        API.

        This then triggers an outbound request from the HS to the target.

        Returns:
            The channel for the *client* request and the *outbound* request for
            the media which the caller should respond to.
        """
        channel = make_request(
            self.reactor,
            self._hs_to_site[hs],
            "GET",
            f"/_matrix/media/r0/download/{target}/{media_id}",
            shorthand=False,
            access_token=self.access_token,
            await_result=False,
        )
        self.pump()

        clients = self.reactor.tcpClients
        self.assertGreaterEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop()

        # build the test server
        server_factory = Factory.forProtocol(HTTPChannel)
        # Request.finish expects the factory to have a 'log' method.
        server_factory.log = _log_request

        server_tls_protocol = wrap_server_factory_for_tls(
            server_factory, self.reactor, sanlist=[b"DNS:example.com"]
        ).buildProtocol(None)

        # now, tell the client protocol factory to build the client protocol (it will be a
        # _WrappingProtocol, around a TLSMemoryBIOProtocol, around an
        # HTTP11ClientProtocol) and wire the output of said protocol up to the server via
        # a FakeTransport.
        #
        # Normally this would be done by the TCP socket code in Twisted, but we are
        # stubbing that out here.
        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(
            FakeTransport(server_tls_protocol, self.reactor, client_protocol)
        )

        # tell the server tls protocol to send its stuff back to the client, too
        server_tls_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, server_tls_protocol)
        )

        # fish the test server back out of the server-side TLS protocol.
        http_server: HTTPChannel = server_tls_protocol.wrappedProtocol

        # give the reactor a pump to get the TLS juices flowing.
        self.reactor.pump((0.1,))

        self.assertEqual(len(http_server.requests), 1)
        request = http_server.requests[0]

        self.assertEqual(request.method, b"GET")
        self.assertEqual(
            request.path,
            f"/_matrix/media/v3/download/{target}/{media_id}".encode(),
        )
        self.assertEqual(
            request.requestHeaders.getRawHeaders(b"host"), [target.encode("utf-8")]
        )

        return channel, request

    @override_config({"enable_authenticated_media": False})
    def test_basic(self) -> None:
        """Test basic fetching of remote media from a single worker."""
        hs1 = self.make_worker_hs("synapse.app.generic_worker")

        channel, request = self._get_media_req(hs1, "example.com:443", "ABC123")

        request.setResponseCode(200)
        request.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request.write(b"Hello!")
        request.finish()

        self.pump(0.1)

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"Hello!")

    @override_config({"enable_authenticated_media": False})
    def test_download_simple_file_race(self) -> None:
        """Test that fetching remote media from two different processes at the
        same time works.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_media()

        # Make two requests without responding to the outbound media requests.
        channel1, request1 = self._get_media_req(hs1, "example.com:443", "ABC123")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "ABC123")

        # Respond to the first outbound media request and check that the client
        # request is successful
        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request1.write(b"Hello!")
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], b"Hello!")

        # Now respond to the second with the same content.
        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request2.write(b"Hello!")
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], b"Hello!")

        # We expect only one new file to have been persisted.
        self.assertEqual(start_count + 1, self._count_remote_media())

    @override_config({"enable_authenticated_media": False})
    def test_download_image_race(self) -> None:
        """Test that fetching remote *images* from two different processes at
        the same time works.

        This checks that races generating thumbnails are handled correctly.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_thumbnails()

        channel1, request1 = self._get_media_req(hs1, "example.com:443", "PIC1")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "PIC1")

        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(b"Content-Type", [b"image/png"])
        request1.write(SMALL_PNG)
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], SMALL_PNG)

        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(b"Content-Type", [b"image/png"])
        request2.write(SMALL_PNG)
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], SMALL_PNG)

        # We expect only three new thumbnails to have been persisted.
        self.assertEqual(start_count + 3, self._count_remote_thumbnails())

    def _count_remote_media(self) -> int:
        """Count the number of files in our remote media directory."""
        media_repo = self.hs.get_media_repository()
        assert isinstance(media_repo, MediaRepository)
        path = os.path.join(media_repo.primary_base_path, "remote_content")
        return sum(len(files) for _, _, files in os.walk(path))

    def _count_remote_thumbnails(self) -> int:
        """Count the number of files in our remote thumbnails directory."""
        media_repo = self.hs.get_media_repository()
        assert isinstance(media_repo, MediaRepository)
        path = os.path.join(media_repo.primary_base_path, "remote_thumbnail")
        return sum(len(files) for _, _, files in os.walk(path))


class AuthenticatedMediaRepoShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks running multiple media repos work correctly using autheticated media paths"""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        media.register_servlets,
    ]

    file_data = b"\r\n\r\n--6067d4698f8d40a0a794ea7d7379d53a\r\nContent-Type: application/json\r\n\r\n{}\r\n--6067d4698f8d40a0a794ea7d7379d53a\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename=test_upload\r\n\r\nfile_to_stream\r\n--6067d4698f8d40a0a794ea7d7379d53a--\r\n\r\n"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = self.register_user("user", "pass")
        self.access_token = self.login("user", "pass")

        self.reactor.lookups["example.com"] = "1.2.3.4"

    def default_config(self) -> dict:
        conf = super().default_config()
        conf["federation_custom_ca_list"] = [get_test_ca_cert_file()]
        return conf

    def make_worker_hs(
        self, worker_app: str, extra_config: Optional[dict] = None, **kwargs: Any
    ) -> HomeServer:
        worker_hs = super().make_worker_hs(worker_app, extra_config, **kwargs)
        # Force the media paths onto the replication resource.
        worker_hs.get_media_repository_resource().register_servlets(
            self._hs_to_site[worker_hs].resource, worker_hs
        )
        return worker_hs

    def _get_media_req(
        self, hs: HomeServer, target: str, media_id: str
    ) -> Tuple[FakeChannel, Request]:
        """Request some remote media from the given HS by calling the download
        API.

        This then triggers an outbound request from the HS to the target.

        Returns:
            The channel for the *client* request and the *outbound* request for
            the media which the caller should respond to.
        """
        channel = make_request(
            self.reactor,
            self._hs_to_site[hs],
            "GET",
            f"/_matrix/client/v1/media/download/{target}/{media_id}",
            shorthand=False,
            access_token=self.access_token,
            await_result=False,
        )
        self.pump()

        clients = self.reactor.tcpClients
        self.assertGreaterEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop()

        # build the test server
        server_factory = Factory.forProtocol(HTTPChannel)
        # Request.finish expects the factory to have a 'log' method.
        server_factory.log = _log_request

        server_tls_protocol = wrap_server_factory_for_tls(
            server_factory, self.reactor, sanlist=[b"DNS:example.com"]
        ).buildProtocol(None)

        # now, tell the client protocol factory to build the client protocol (it will be a
        # _WrappingProtocol, around a TLSMemoryBIOProtocol, around an
        # HTTP11ClientProtocol) and wire the output of said protocol up to the server via
        # a FakeTransport.
        #
        # Normally this would be done by the TCP socket code in Twisted, but we are
        # stubbing that out here.
        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(
            FakeTransport(server_tls_protocol, self.reactor, client_protocol)
        )

        # tell the server tls protocol to send its stuff back to the client, too
        server_tls_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, server_tls_protocol)
        )

        # fish the test server back out of the server-side TLS protocol.
        http_server: HTTPChannel = server_tls_protocol.wrappedProtocol

        # give the reactor a pump to get the TLS juices flowing.
        self.reactor.pump((0.1,))

        self.assertEqual(len(http_server.requests), 1)
        request = http_server.requests[0]

        self.assertEqual(request.method, b"GET")
        self.assertEqual(
            request.path,
            f"/_matrix/federation/v1/media/download/{media_id}".encode(),
        )
        self.assertEqual(
            request.requestHeaders.getRawHeaders(b"host"), [target.encode("utf-8")]
        )

        return channel, request

    def test_basic(self) -> None:
        """Test basic fetching of remote media from a single worker."""
        hs1 = self.make_worker_hs("synapse.app.generic_worker")

        channel, request = self._get_media_req(hs1, "example.com:443", "ABC123")

        request.setResponseCode(200)
        request.responseHeaders.setRawHeaders(
            b"Content-Type",
            ["multipart/mixed; boundary=6067d4698f8d40a0a794ea7d7379d53a"],
        )
        request.write(self.file_data)
        request.finish()

        self.pump(0.1)

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"file_to_stream")

    def test_download_simple_file_race(self) -> None:
        """Test that fetching remote media from two different processes at the
        same time works.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_media()

        # Make two requests without responding to the outbound media requests.
        channel1, request1 = self._get_media_req(hs1, "example.com:443", "ABC123")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "ABC123")

        # Respond to the first outbound media request and check that the client
        # request is successful
        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(
            b"Content-Type",
            ["multipart/mixed; boundary=6067d4698f8d40a0a794ea7d7379d53a"],
        )
        request1.write(self.file_data)
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], b"file_to_stream")

        # Now respond to the second with the same content.
        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(
            b"Content-Type",
            ["multipart/mixed; boundary=6067d4698f8d40a0a794ea7d7379d53a"],
        )
        request2.write(self.file_data)
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], b"file_to_stream")

        # We expect only one new file to have been persisted.
        self.assertEqual(start_count + 1, self._count_remote_media())

    def test_download_image_race(self) -> None:
        """Test that fetching remote *images* from two different processes at
        the same time works.

        This checks that races generating thumbnails are handled correctly.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_thumbnails()

        channel1, request1 = self._get_media_req(hs1, "example.com:443", "PIC1")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "PIC1")

        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(
            b"Content-Type",
            ["multipart/mixed; boundary=6067d4698f8d40a0a794ea7d7379d53a"],
        )
        img_data = b"\r\n\r\n--6067d4698f8d40a0a794ea7d7379d53a\r\nContent-Type: application/json\r\n\r\n{}\r\n--6067d4698f8d40a0a794ea7d7379d53a\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=test_img\r\n\r\n"
        request1.write(img_data)
        request1.write(SMALL_PNG)
        request1.write(b"\r\n--6067d4698f8d40a0a794ea7d7379d53a--\r\n\r\n")
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], SMALL_PNG)

        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(
            b"Content-Type",
            ["multipart/mixed; boundary=6067d4698f8d40a0a794ea7d7379d53a"],
        )
        request2.write(img_data)
        request2.write(SMALL_PNG)
        request2.write(b"\r\n--6067d4698f8d40a0a794ea7d7379d53a--\r\n\r\n")
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], SMALL_PNG)

        # We expect only three new thumbnails to have been persisted.
        self.assertEqual(start_count + 3, self._count_remote_thumbnails())

    def _count_remote_media(self) -> int:
        """Count the number of files in our remote media directory."""
        media_repo = self.hs.get_media_repository()
        assert isinstance(media_repo, MediaRepository)
        path = os.path.join(media_repo.primary_base_path, "remote_content")
        return sum(len(files) for _, _, files in os.walk(path))

    def _count_remote_thumbnails(self) -> int:
        """Count the number of files in our remote thumbnails directory."""
        media_repo = self.hs.get_media_repository()
        assert isinstance(media_repo, MediaRepository)
        path = os.path.join(media_repo.primary_base_path, "remote_thumbnail")
        return sum(len(files) for _, _, files in os.walk(path))


class CopyRestrictedResourceReplicationTestCase(BaseMultiWorkerStreamTestCase):
    """
    Tests copy API when `msc3911_enabled` is configured to be True.
    """

    servlets = [
        # media.register_servlets,
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    # def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
    #     return self.setup_test_homeserver(config=config)

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config.update(
            {
                "experimental_features": {"msc3911_enabled": True},
                "media_repo_instances": ["media_worker_1"],
            }
        )
        config["instance_map"] = {
            "main": {"host": "testserv", "port": 8765},
            "media_worker_1": {"host": "testserv", "port": 1001},
        }

        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # self.media_repo = hs.get_media_repository()
        self.profile_handler = self.hs.get_profile_handler()
        self.user = self.register_user("user", "testpass")
        self.user_tok = self.login("user", "testpass")
        self.other_user = self.register_user("other", "testpass")
        self.other_user_tok = self.login("other", "testpass")

    def make_worker_hs(
        self, worker_app: str, extra_config: Optional[dict] = None, **kwargs: Any
    ) -> HomeServer:
        worker_hs = super().make_worker_hs(worker_app, extra_config, **kwargs)
        # Force the media paths onto the replication resource.
        worker_hs.get_media_repository_resource().register_servlets(
            self._hs_to_site[worker_hs].resource, worker_hs
        )
        media.register_servlets(worker_hs, self._hs_to_site[worker_hs].resource)
        return worker_hs

    def fetch_media(
        self,
        hs: HomeServer,
        mxc_uri: MXCUri,
        access_token: Optional[str] = None,
        expected_code: int = 200,
    ) -> FakeChannel:
        """
        Test retrieving the media. We do not care about the content of the media, just
        that the response is correct
        """
        channel = make_request(
            self.reactor,
            self._hs_to_site[hs],
            "GET",
            f"/_matrix/client/v1/media/download/{mxc_uri.server_name}/{mxc_uri.media_id}",
            access_token=access_token,
        )
        assert channel.code == expected_code, channel.code
        return channel

    def test_copy_local_restricted_resource(self) -> None:
        """
        Tests that the new copy endpoint creates a new mxc uri for restricted resource.
        """
        media_worker = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "media_worker_1"}
        )
        media_repo = media_worker.get_media_repository()

        # Create a private room
        room_id = self.helper.create_room_as(
            self.user,
            is_public=False,
            tok=self.user_tok,
            extra_content={
                "initial_state": [
                    {
                        "type": EventTypes.RoomHistoryVisibility,
                        "state_key": "",
                        "content": {"history_visibility": HistoryVisibility.JOINED},
                    },
                ]
            },
        )
        # Invite the other user
        self.helper.invite(room_id, self.user, self.other_user, tok=self.user_tok)
        self.helper.join(room_id, self.other_user, tok=self.other_user_tok)

        # The media is created with user_tok
        content = io.BytesIO(SMALL_PNG)
        content_uri = self.get_success(
            media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                content,
                67,
                UserID.from_string(self.user),
                restricted=True,
            )
        )
        media_id = content_uri.media_id

        # User sends a message with media
        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/send/m.room.message/{str(time.time())}?org.matrix.msc3911.attach_media={str(content_uri)}",
            content={"msgtype": "m.text", "body": "Hi, this is a message"},
            access_token=self.user_tok,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        assert "event_id" in channel.json_body
        event_id = channel.json_body["event_id"]
        restrictions = self.get_success(
            self.hs.get_datastores().main.get_media_restrictions(
                content_uri.server_name, content_uri.media_id
            )
        )
        assert restrictions is not None, str(restrictions)
        assert restrictions.event_id == event_id

        # The other_user copies the media from local server
        channel = make_request(
            self.reactor,
            self._hs_to_site[media_worker],
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{self.hs.hostname}/{media_id}",
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 200)
        self.assertIn("content_uri", channel.json_body)
        new_media_id = channel.json_body["content_uri"].split("/")[-1]
        assert new_media_id != media_id

        # Check if the original media there.
        original_media = self.get_success(
            self.hs.get_datastores().main.get_local_media(media_id)
        )
        assert original_media is not None
        assert original_media.user_id == self.user

        # Check the copied media.
        copied_media = self.get_success(
            self.hs.get_datastores().main.get_local_media(new_media_id)
        )
        assert copied_media is not None
        assert copied_media.user_id == self.other_user

        # Check if they are referencing the same image.
        assert original_media.sha256 == copied_media.sha256

        # Check if media is unattached to any event or user profile yet.
        assert copied_media.attachments is None

        original_media_download = self.fetch_media(
            media_worker,
            MXCUri.from_str(f"mxc://{self.hs.hostname}/{media_id}"),
            self.user_tok,
        )
        # This is a hex encoded byte stream of the raw file
        old_media_payload = original_media_download.result.get("body")
        assert old_media_payload is not None, old_media_payload

        new_media_download = self.fetch_media(
            media_worker,
            MXCUri.from_str(f"mxc://{self.hs.hostname}/{new_media_id}"),
            self.other_user_tok,
        )
        # Again, a hex encoded byte stream of the raw file
        new_media_payload = new_media_download.result.get("body")
        assert new_media_payload is not None

        # If they match, this was a successful copy
        assert old_media_payload == new_media_payload

    def test_copy_local_restricted_resource_fails_when_requester_does_not_have_access(
        self,
    ) -> None:
        """
        Tests that the new copy endpoint performs permission checks and it prevents the
        copy when the requester does not have access to the original media.
        """
        media_worker = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "media_worker_1"}
        )
        media_repo = media_worker.get_media_repository()

        # Create a private room
        room_id = self.helper.create_room_as(
            self.user,
            is_public=False,
            tok=self.user_tok,
            extra_content={
                "initial_state": [
                    {
                        "type": EventTypes.RoomHistoryVisibility,
                        "state_key": "",
                        "content": {"history_visibility": HistoryVisibility.JOINED},
                    },
                ]
            },
        )

        # Create the media content
        content_uri = self.get_success(
            media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(self.user),
                restricted=True,
            )
        )
        # User sends a message with media
        channel = self.make_request(
            "PUT",
            f"/rooms/{room_id}/send/m.room.message/{str(time.time())}?org.matrix.msc3911.attach_media={str(content_uri)}",
            content={"msgtype": "m.text", "body": "Hi, this is a message"},
            access_token=self.user_tok,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        assert "event_id" in channel.json_body
        event_id = channel.json_body["event_id"]
        restrictions = self.get_success(
            self.hs.get_datastores().main.get_media_restrictions(
                content_uri.server_name, content_uri.media_id
            )
        )
        assert restrictions is not None, str(restrictions)
        assert restrictions.event_id == event_id

        # Invite the other user
        self.helper.invite(room_id, self.user, self.other_user, tok=self.user_tok)
        self.helper.join(room_id, self.other_user, tok=self.other_user_tok)

        # User who does not have access to the media tries to copy it.
        channel = make_request(
            self.reactor,
            self._hs_to_site[media_worker],
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{self.hs.hostname}/{content_uri.media_id}",
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 403)

    @override_config(
        {
            "limit_profile_requests_to_users_who_share_rooms": True,
        }
    )
    def test_copy_local_restricted_resource_fails_when_profile_lookup_is_not_allowed(
        self,
    ) -> None:
        media_worker = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "media_worker_1"}
        )
        media_repo = media_worker.get_media_repository()
        # User setup a profile
        content_uri = self.get_success(
            media_repo.create_or_update_content(
                "image/png",
                "test_png_upload",
                io.BytesIO(SMALL_PNG),
                67,
                UserID.from_string(self.user),
                restricted=True,
            )
        )
        user_id = UserID.from_string(self.user)
        self.get_success(
            self.profile_handler.set_avatar_url(
                user_id, create_requester(user_id), str(content_uri)
            )
        )
        # The users do not share any rooms, and other user tries to copy the profile picture
        channel = make_request(
            self.reactor,
            self._hs_to_site[media_worker],
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{self.hs.hostname}/{content_uri.media_id}",
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 403)

    def test_copy_remote_restricted_resource(self) -> None:
        """
        Tests that the new copy endpoint creates a new mxc uri for restricted resource.
        """
        media_worker = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "media_worker_1"}
        )
        media_repo = media_worker.get_media_repository()
        # create remote media
        remote_server = "remoteserver.com"
        media_id = "remotemedia"
        remote_file_id = media_id
        file_info = FileInfo(server_name=remote_server, file_id=remote_file_id)

        assert isinstance(media_repo, MediaRepository)
        media_storage = media_repo.media_storage
        ctx = media_storage.store_into_file(file_info)
        (f, _) = self.get_success(ctx.__aenter__())
        f.write(SMALL_PNG)
        self.get_success(ctx.__aexit__(None, None, None))
        self.get_success(
            # The main store will not have authenticated media enabled, use the media repo
            media_repo.store.store_cached_remote_media(
                origin=remote_server,
                media_id=media_id,
                media_type="image/png",
                media_length=67,
                time_now_ms=self.clock.time_msec(),
                upload_name="test.png",
                filesystem_id=remote_file_id,
                sha256=SMALL_PNG_SHA256,
                restricted=True,
            )
        )

        # Remote media is attached to a user profile
        remote_user_id = f"@remote-user:{remote_server}"
        self.get_success(
            self.hs.get_datastores().main.set_media_restricted_to_user_profile(
                remote_server, media_id, remote_user_id
            )
        )
        remote_media = self.get_success(
            self.hs.get_datastores().main.get_cached_remote_media(
                remote_server, media_id
            )
        )
        assert remote_media is not None
        assert remote_media.attachments is not None
        assert str(remote_media.attachments.profile_user_id) == remote_user_id

        # The other_user copies the media from remote server
        channel = make_request(
            self.reactor,
            self._hs_to_site[media_worker],
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{remote_server}/{media_id}",
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 200)
        self.assertIn("content_uri", channel.json_body)
        new_media_id = channel.json_body["content_uri"].split("/")[-1]
        assert new_media_id != media_id

        # Check if the original media there.
        original_media = self.get_success(
            self.hs.get_datastores().main.get_cached_remote_media(
                remote_server, media_id
            )
        )
        assert original_media is not None
        assert original_media.upload_name == "test.png"

        # Check the copied media.
        copied_media = self.get_success(
            self.hs.get_datastores().main.get_local_media(new_media_id)
        )
        assert copied_media is not None
        assert copied_media.user_id == self.other_user

        # Check if they are referencing the same image.
        assert original_media.sha256 == copied_media.sha256

        # Check if copied media is unattached to any event or user profile yet.
        assert copied_media.attachments is None

        original_media_download = self.fetch_media(
            media_worker,
            MXCUri.from_str(f"mxc://{remote_server}/{media_id}"),
            self.user_tok,
        )
        # This is a hex encoded byte stream of the raw file
        old_media_payload = original_media_download.result.get("body")
        assert old_media_payload is not None, old_media_payload

        new_media_download = self.fetch_media(
            media_worker,
            MXCUri.from_str(f"mxc://{self.hs.hostname}/{new_media_id}"),
            self.other_user_tok,
        )
        # Again, a hex encoded byte stream of the raw file
        new_media_payload = new_media_download.result.get("body")
        assert new_media_payload is not None

        # If they match, this was a successful copy
        assert old_media_payload == new_media_payload

    @override_config(
        {
            "limit_profile_requests_to_users_who_share_rooms": True,
        }
    )
    def test_copy_remote_restricted_resource_fails_when_requester_does_not_have_access(
        self,
    ) -> None:
        media_worker = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "media_worker_1"}
        )
        media_repo = media_worker.get_media_repository()

        # Create remote media
        remote_server = "remoteserver.com"
        remote_file_id = "remote1"
        file_info = FileInfo(server_name=remote_server, file_id=remote_file_id)

        assert isinstance(media_repo, MediaRepository)
        media_storage = media_repo.media_storage
        ctx = media_storage.store_into_file(file_info)
        (f, _) = self.get_success(ctx.__aenter__())
        f.write(SMALL_PNG)
        self.get_success(ctx.__aexit__(None, None, None))
        media_id = "remotemedia"
        self.get_success(
            # The main data store will not have authenticated media enabled, use the media repo
            media_repo.store.store_cached_remote_media(
                origin=remote_server,
                media_id=media_id,
                media_type="image/png",
                media_length=1,
                time_now_ms=self.clock.time_msec(),
                upload_name="test.png",
                filesystem_id=remote_file_id,
                sha256=remote_file_id,
                restricted=True,
            )
        )

        # Media is attached to a user profile
        remote_user_id = f"@remote-user:{remote_server}"
        self.get_success(
            self.hs.get_datastores().main.set_media_restricted_to_user_profile(
                remote_server, media_id, remote_user_id
            )
        )
        remote_media = self.get_success(
            self.hs.get_datastores().main.get_cached_remote_media(
                remote_server, media_id
            )
        )
        assert remote_media is not None
        assert remote_media.attachments is not None
        assert str(remote_media.attachments.profile_user_id) == remote_user_id

        # The other user tries to copy that media from remote server, but fails because
        # user does not have the access to the profile_user_id
        channel = make_request(
            self.reactor,
            self._hs_to_site[media_worker],
            "POST",
            f"/_matrix/client/unstable/org.matrix.msc3911/media/copy/{remote_server}/{media_id}",
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 403)


def _log_request(request: Request) -> None:
    """Implements Factory.log, which is expected by Request.finish"""
    logger.info("Completed request %s", request)
