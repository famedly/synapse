#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright (C) 2026 Famedly GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#

from typing import Any

from synapse.config._base import Config, ConfigError
from synapse.types import JsonDict

VALID_TIM_VERSIONS = ("1.1", "1.2")


class TimConfig(Config):
    """Config section for TIM-specific settings."""

    section = "tim"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        tim_version = config.get("tim_version", "1.1")

        if tim_version not in VALID_TIM_VERSIONS:
            raise ConfigError(
                f"tim_version must be one of {', '.join(VALID_TIM_VERSIONS)}, "
                f"got {tim_version!r}",
                ("tim_version",),
            )

        self.tim_version: str = tim_version
