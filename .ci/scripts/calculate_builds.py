#!/usr/bin/env python
#
# Copyright (C) 2025 Famedly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

#

# Produce the mod pack build options to translate into tags for the docker image

import json
import os
from typing import Any


def set_output(key: str, value: str) -> None:
    # See https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter
    # The mode to use is "at", which means 'append' and 'text' mode. This appends new
    # 'key' and 'value' pairs to the Github environment separated by a single space
    with open(os.environ["GITHUB_OUTPUT"], "at") as f:
        print(f"{key}={value}", file=f)


# INSTRUCTIONS:
#

# As new module versions are released, update the newest 'modxxx' variant to include
# them. These will then be referenced further down to decide which mod packs are to be
# built
all_mod_pack_versions = {
    "mod001": {"sic-version": "0.2.0", "sta-version": "0.5.0"},
    "mod002": {"sic-version": "0.2.0", "sta-version": "0.6.0"},
    "mod003": {"sic-version": "0.2.0", "sta-version": "0.8.1"},
    # mod004 should be the final TIM 1.1
    "mod004": {"sic-version": "0.2.0", "sta-version": "0.9.0"},
    "mod005": {"sic-version": "0.4.1", "sta-version": "0.9.0"},
    "mod006": {"sic-version": "0.4.1", "sta-version": "0.11.0"},
    "mod007": {"sic-version": "0.4.2", "sta-version": "0.11.0"},
    "mod008": {"sic-version": "0.4.3", "sta-version": "0.11.0"},
    "mod009": {"sic-version": "0.4.4", "sta-version": "0.11.0"},
    "mod010": {"sic-version": "0.4.5", "sta-version": "0.11.0"},
    "mod011": {"sic-version": "0.4.6", "sta-version": "0.11.0"},
    "mod012": {"sic-version": "0.4.7", "sta-version": "0.11.0"},
    "mod013": {"sic-version": "0.4.7", "sta-version": "0.12.0"},
    "mod014": {"sic-version": "0.4.8", "sta-version": "0.12.0"},
    "mod015": {"sic-version": "0.4.9", "sta-version": "0.12.0"},
}

# Adjust this section to decide what gets built and layered on top
# THIS IS THE SECTION TO EDIT, after you have added the new versions above
current_mod_packs_to_build = ["mod004", "mod015"]

generated_jobs: list[dict[str, Any]] = []
for mod_pack_job in current_mod_packs_to_build:
    version_data = all_mod_pack_versions.get(mod_pack_job, {})
    if not version_data:
        msg = f"version data for '{mod_pack_job}' was not found. Did you add it to 'all_mod_pack_versions'?"
        raise Exception(msg)
    assert version_data is not None
    # Mutate what is returned slightly. We will need the name of the modpack to suffix
    # to the docker image tag. This will be picked up by the docker
    version_data.update({"mod_pack_name": mod_pack_job})
    generated_jobs.append(version_data)


print("::group::Calculated build jobs")
print(json.dumps(generated_jobs, indent=4))
print("::endgroup::")

build_matrix = json.dumps(generated_jobs)
set_output("build_matrix", build_matrix)
