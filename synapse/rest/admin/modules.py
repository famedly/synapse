import logging
from http import HTTPStatus
from typing import TYPE_CHECKING

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from synapse.types import JsonDict
from synapse.util.module_loader import get_loaded_module_information

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ModulesRestServlet(RestServlet):
    """An admin API to get information about loaded modules and their versions.

    Example:
        GET /_synapse/admin/v1/modules
        200 OK
        {
            "modules": [
                {
                    "module_name": "mjolnir.antispam.Module",
                    "package_name": "mjolnir"
                    "version": "1.2.3"
                }
            ]
        }
    """

    PATTERNS = admin_patterns("/modules$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.hs = hs

    async def on_GET(self, request: SynapseRequest) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        modules_info = []

        # Get loaded modules from the homeserver config
        for module, _config in self.hs.config.modules.loaded_modules:
            package_name, module_name, module_version = get_loaded_module_information(
                module
            )

            modules_info.append(
                {
                    "package_name": package_name,
                    "module_name": module_name,
                    "version": module_version,
                }
            )

        return HTTPStatus.OK, {"modules": modules_info}
