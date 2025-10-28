#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from typing import Dict
from unittest.mock import patch

from synapse.util.module_loader import get_loaded_module_information

from tests.unittest import TestCase


class DummyModuleWithVersion:
    __module__ = "dummy_package.submodule"
    __name__ = "DummyModuleWithVersion"
    __version__ = "1.0.0"


class DummyModuleWithoutVersion:
    __module__ = "another_package.core"
    __name__ = "DummyModuleWithoutVersion"


class NestedModuleClass:
    __module__ = "deeply.nested.package.module"
    __name__ = "NestedModuleClass"


class SimpleModuleClass:
    __module__ = "simplepackage"
    __name__ = "SimpleModuleClass"


class ModuleLoaderTestCase(TestCase):
    def test_get_loaded_module_information_with_package_version(self) -> None:
        mock_packages_distributions: Dict[str, list] = {
            "dummy_package": ["dummy_package"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch("synapse.util.module_loader.version", return_value="2.3.4"):
                package_name, module_name, module_version = (
                    get_loaded_module_information(DummyModuleWithVersion)
                )

                self.assertEqual(package_name, "dummy_package")
                self.assertEqual(
                    module_name, "dummy_package.submodule.DummyModuleWithVersion"
                )
                self.assertEqual(module_version, "2.3.4")

    def test_get_loaded_module_information_with_module_version_fallback(
        self,
    ) -> None:
        from importlib.metadata import PackageNotFoundError

        mock_packages_distributions: Dict[str, list] = {
            "dummy_package": ["dummy_package"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch(
                "synapse.util.module_loader.version",
                side_effect=PackageNotFoundError,
            ):
                package_name, module_name, module_version = (
                    get_loaded_module_information(DummyModuleWithVersion)
                )

                self.assertEqual(package_name, "dummy_package")
                self.assertEqual(
                    module_name, "dummy_package.submodule.DummyModuleWithVersion"
                )
                self.assertEqual(module_version, "1.0.0")

    def test_get_loaded_module_information_with_unknown_version(self) -> None:
        from importlib.metadata import PackageNotFoundError

        mock_packages_distributions: Dict[str, list] = {
            "another_package": ["another_package"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch(
                "synapse.util.module_loader.version",
                side_effect=PackageNotFoundError,
            ):
                package_name, module_name, module_version = (
                    get_loaded_module_information(DummyModuleWithoutVersion)
                )

                self.assertEqual(package_name, "another_package")
                self.assertEqual(
                    module_name, "another_package.core.DummyModuleWithoutVersion"
                )
                self.assertEqual(module_version, "unknown")

    def test_get_loaded_module_information_nested_package(self) -> None:
        mock_packages_distributions: Dict[str, list] = {
            "deeply": ["deeply-nested-package"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch("synapse.util.module_loader.version", return_value="3.1.4"):
                package_name, module_name, module_version = (
                    get_loaded_module_information(NestedModuleClass)
                )

                self.assertEqual(package_name, "deeply-nested-package")
                self.assertEqual(
                    module_name, "deeply.nested.package.module.NestedModuleClass"
                )
                self.assertEqual(module_version, "3.1.4")

    def test_get_loaded_module_information_simple_package(self) -> None:
        mock_packages_distributions: Dict[str, list] = {
            "simplepackage": ["simplepackage"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch("synapse.util.module_loader.version", return_value="0.9.0"):
                package_name, module_name, module_version = (
                    get_loaded_module_information(SimpleModuleClass)
                )

                self.assertEqual(package_name, "simplepackage")
                self.assertEqual(module_name, "simplepackage.SimpleModuleClass")
                self.assertEqual(module_version, "0.9.0")

    def test_get_loaded_module_information_multiple_distributions(self) -> None:
        mock_packages_distributions: Dict[str, list] = {
            "dummy_package": ["dummy-pkg-dist", "dummy-pkg-alt"]
        }

        with patch(
            "synapse.util.module_loader.packages_distributions",
            return_value=mock_packages_distributions,
        ):
            with patch("synapse.util.module_loader.version", return_value="1.2.3"):
                package_name, module_name, module_version = (
                    get_loaded_module_information(DummyModuleWithVersion)
                )

                # Should use the first distribution in the list
                self.assertEqual(package_name, "dummy-pkg-dist")
                self.assertEqual(
                    module_name, "dummy_package.submodule.DummyModuleWithVersion"
                )
                self.assertEqual(module_version, "1.2.3")
