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

from synapse.config import ConfigError
from synapse.config.homeserver import HomeServerConfig

from tests.unittest import TestCase
from tests.utils import default_config


class TimConfigTestCase(TestCase):
    def _parse_config(self, extra: dict) -> HomeServerConfig:
        config_dict = {**default_config("test"), **extra}
        config = HomeServerConfig()
        config.parse_config_dict(config_dict, "", "")
        return config

    def test_default_tim_version(self) -> None:
        """tim_version defaults to '1.1' when not set."""
        config = self._parse_config({})
        self.assertEqual(config.tim.tim_version, "1.1")

    def test_tim_version_1_1(self) -> None:
        """tim_version can be explicitly set to '1.1'."""
        config = self._parse_config({"tim_version": "1.1"})
        self.assertEqual(config.tim.tim_version, "1.1")

    def test_tim_version_1_2(self) -> None:
        """tim_version can be set to '1.2'."""
        config = self._parse_config({"tim_version": "1.2"})
        self.assertEqual(config.tim.tim_version, "1.2")

    def test_invalid_tim_version_rejected(self) -> None:
        """An invalid tim_version should raise ConfigError."""
        with self.assertRaises(ConfigError):
            self._parse_config({"tim_version": "2.0"})

    def test_invalid_tim_version_string(self) -> None:
        """A non-version string should raise ConfigError."""
        with self.assertRaises(ConfigError):
            self._parse_config({"tim_version": "invalid"})

    def test_invalid_tim_version_numeric(self) -> None:
        """A numeric (non-string) tim_version should raise ConfigError."""
        with self.assertRaises(ConfigError):
            self._parse_config({"tim_version": 1.1})
