#!/bin/bash

set -e

# For a given argument that is a release version, it will be the tag. For now, want the
# format of `vX.Y.Z_A`. The underscore and `A` is important to include, as that is the
# Famedly patch version that is separate from the upstream patch version
release_name=$1

if [ -z "${release_name}" ]; then
    echo "Usage: $0 <release_name in vX.Y.Z_A format>"
    exit 1
fi

if [ "${release_name}" = "-h" ]; then
    echo "Usage: $0 <release_name in vX.Y.Z_A format>"
    exit 0
fi

# The major-minor number of the version, so of the release_name above which looks like `vX.Y.Z_A`,
# we want the `vX.Y`
release_major_minor=${release_name%.*}

# What our branch name will be. Upstream uses the format of `release-vX.Y` so to avoid
# confusion we will pre-pend 'famedly' to that and use a `/` to namespace it. Like this:
# `famedly-release/vX.Y`. We do want patch levels and hotfixes to live on the same
# branch as the release major.minor
release_branch_name="famedly-release/${release_major_minor}"

echo -e "\e[32m>>>> fetching origin branches\e[0m"
# If the release_name that was passed already exists as a tag, this will fatal error.
# Make sure it does not legitimately exist, or that you really mean to replace it before
# running `git tag -d <release_name>` to remove that one single tag
set +e
if ! git fetch --tags origin; then
  echo "This tag appears to already exist, would you like to delete that tag so it can be forcibly replaced?"
  read -n 1 -p "Press y to delete, or any other key to exit ${\n}" input_key
  if [[ $input_key == "y"]]; then
    git tag -d $release_name
  else
    exit 1
  fi
fi


set -e
echo -e "\e[32m>>>> find/checkout release branch\e[0m"
# Disable error catching for a moment, that we may tell the user a more explicit error
# message than 'fatal'
set +e
if ! git switch "$release_branch_name"; then
  echo "The Famedly release branch for this version of Synapse seems to be missing. Was it already created?"
  exit 1
fi
set -e


read -n 1 -p "Press 'p' to push branch to Github, or any other key to skip\n" input_key
if [[ $input_key == "p" ]]; then
  echo -e "\e[32m>>>> pushing release branch\e[0m"
  git push --force -u origin "${release_branch_name}"
fi

read -n 1 -p "Press 't' to run linting and tests, or any other key to skip\n" input_key
if [[ $input_key == "t" ]]; then
  echo -e "\e[32m>>>> running lint and tests...\e[0m"
  # Make sure there are no weirdities around poetry. Until the deprecation migration
  # occurs, expect orange things to read here.
  poetry check
  poetry install --extras all --no-interaction
  poetry run ./scripts-dev/lint.sh

  logical_cores=$([ $(uname) = 'Darwin' ] &&
                         sysctl -n hw.logicalcpu_max ||
                         nproc)

  poetry run trial -j"${logical_cores}" tests
  echo -e "\e[32m>>>> Success!\e[0m"
fi

read -n 1 -p "Press 't' to create tag and push to Github, or any other key to skip\n" input_key
if [[ $input_key == "t" ]]; then
  echo -e "\e[32m>>>> updating release tag\e[0m"
  git tag -f -s -m "${release_name}" "${release_name}"
  git push -f origin "${release_name}"
fi
echo -e "\e[32m>>>> Finished!\e[0m"
