#!/bin/bash

# The script to merge in upstream changes.
# Provide an argument of the release major-minor, in the format of `vX.Y`. For example:
# `v1.123`. Detection will run looking for upstream release branch of that version.
#
# Three scenarios are handled by this script:
# 1. New minor version(updating from `v1.123` to `v1.124`)
# 2. Existing minor version with an upstream patch increment(updating from `v1.123.0` to
#    `v1.123.1`)
# 3. Existing patch version with a local Famedly level patch increment(updating from
#    `v1.123.1_1` to `v1.123.1_2`)
#
# If the provided release version does not exist on this repo, it will be created.
# If it already exists on this repo, even remotely, it will be found and then checked
# out.
# After resolving this branch, the appropriate upstream changes will be merged in if
# they exist. If a merge conflict arises from merging in upstream, the script will exit.
# Once any conflicts are resolved, `git add` and `git merge --continue` need to be ran.
# Then, run this script again with the same argument to proceed with the next step. If
# you have not correctly commited the changes from a conflict, they will be lost.
# When there are no upstream changes and only local changes, the Famedly
# patch level is incremented. No tags are generated in this script.
# After the merge is completed, the CHANGES.md file is updated to include any changes
# exclusive to Famedly's repo. These changes will be placed at the bottom of the current
# most entry. Successive Famedly additions will stay in order, appended after.
set -e

release_name=$1

if [ -z "${release_name}" ]; then
    echo "Usage: $0 <release_name in vX.Y format>"
    exit 1
fi

if [ "${release_name}" = "-h" ]; then
    echo "Usage: $0 <release_name in vX.Y format>"
    exit 0
fi

# The minor number of the version, so of the release_name above which looks like `vX.Y`,
# we are peeling off the `Y` for further use
expected_minor=${release_name##*.}

# What our branch name will be. Upstream uses the format of `release-vX.Y` so to avoid
# confusion we will pre-pend 'famedly' to that and use a `/` to namespace it. Like this:
# `famedly-release/vX.Y`. We do want patch levels and hotfixes to live on the same
# branch as the release major.minor
release_branch_name="famedly-release/${release_name}"

# The upstream repo's version appropriate branch name
upstream_release_branch_name="release-${release_name}"

echo -e "\e[32m>>>> fetching origin branches\e[0m"
# If the release_name that was passed already exists as a tag, this will fatal error.
# Make sure it does not legitimately exist, or that you really mean to replace it before
# running `git tag -d <release_name>` to remove that one single tag. XXX: this may be wrong now, double check
git fetch --tags origin

echo -e "\e[32m>>>> fetching upstream branches\e[0m"
git fetch --tags upstream

echo -e "\e[32m>>>> checkout master branch\e[0m"
git checkout master
echo -e "\e[32m>>>> resetting master branch\e[0m"
git reset --hard

echo -e "\e[32m>>>> find/checkout release branch\e[0m"
# Temporarily disable error catching, as it will cause the script to halt
# Normally this is not needed, but apparently our chosen branch name for famedly
# releases causes fatal errors if it does not already exist. I believe it is caused by
# the '/' in the branch name and how that can be a confusing reference for git to try
# and sort out.
# Specifically `famedly-release/vX.Y` comes across as 'fatal' instead of just
# 'non-existent'. I choose to blame the '/'
set +e

# Expect this a '0' for exists and a '1' for not-exists. Fatal is a '128'. We apply a
# NOT so the condition only runs if there was an error
if ! git switch "$release_branch_name"; then
  echo "branch did not exist, creating"
  # -c creates the branch at our current checkout. Which should be a clean checkout of
  # the master branch from a moment ago
  git switch -c "$release_branch_name"
fi
# Have to re-enable error catching in case something else breaks
set -e

# Fetch existing tags on this branch. If this was a new branch from main, ours will be the
# last tag added. If this was an existing branch we are appending to, ours will still be
# the last tag added. Note that this may differ from what we are releasing if this the
# initial version the branch contains. For example, if we are merging in `v1.124`, this
# will be `v1.123.0_1` or similar
last_tag_on_this_branch=$(git describe --tags --abbrev=0 --match v*.*.*_*)

# Our patch level version, everything after the `_`
famedly_patch_level=${last_tag_on_this_branch#*_}

# The major, minor and patch level, so `vX.Y.Z`
long_ver=${last_tag_on_this_branch%_*}

# Just the patch level integer, so `Z`
patch_level=${long_ver##*.}

# The `vX.Y`.
major_minor=${long_ver%.*}

# and just the `Y`
minor_ver=${major_minor##*.}


# First determine if the upstream branch has incremented it's patch level. These are in
# the format of `vX.Y.Z`
upstreams_last_tag=$(git ls-remote --tags upstream "$release_name"* | grep -o 'refs/tags/v[0-9]*\.[0-9]*\.[0-9]*' | sort -rV | head -n1 | cut --delimiter='/' --fields=3)
# This should just be the `Z`
upstream_patch_level=${upstreams_last_tag##*.}
# The `vX.Y`
upstream_major_minor=${upstreams_last_tag%.*}
# And just the `Y`
upstream_minor_ver=${upstream_major_minor##.*}

# if upstream patch level has increased, we bump ours too
if [[ "$expected_minor" != "$minor_ver" ]]; then
  # Must have been a version bump which means this is a new minor version release. In
  # this case, it's likely that it is the same as what upstream's is. This resets the
  # Famedly patch level.
  expected_new_version_tag="${upstreams_last_tag}_1"
  echo "Likely new minor version $expected_new_version_tag"

elif [[ "$upstream_patch_level" -gt "$patch_level" ]]; then
  # No minor version bump but there was a patch level version bump, increment our
  # expected patch level and reset the Famedly patch level.
  expected_new_version_tag="${upstreams_last_tag}_1"
  echo "Likely new patch version $expected_new_version_tag"

else
  # No minor and no patch level increase, this is probably just a famedly patch level
  # increase.
  increment_patch_level=$(( famedly_patch_level + 1))
  expected_new_version_tag="${upstreams_last_tag}_$increment_patch_level"
  echo "Likely new famedly patch version $expected_new_version_tag"

fi

echo -e "\e[32m>>>> merging upstream into release branch\e[0m"
# We let this error if there was a merge conflict that needs to be resolved. It should
# be an idempotent process of just rerunning the script to continue on. After a
# `git merge --continue`, of course
set +e
if ! git merge "upstream/release-${release_name}" -m "Famedly ${release_name}"; then
  echo "An error was detected. Fix the conflicts, 'git add' the changes, run 'git merge --continue' and re-run this script with the same arguments"
  exit 1
fi
set -e

# Retrieve the git log entries themselves and format them to fit well into the
# markdown format. If there were none, we can skip this whole next section. This will
# only pull the changes between the lastest tag found on this branch and master when the
# tag is in our format and discards merges
git_log_output=$(git log $(git describe --tags --abbrev=0 --match v*.*.*_*)..master --pretty=format:'- %s %C(bold blue)(%an)%Creset\' --no-merges --no-decorate)
if [[ ! -z "$git_log_output" ]]; then
  echo -e "\n"
  echo "Note: Entries to be added to the CHANGES.md file are detected. I can do this automatically for you."
  echo -e "\e[31m WARNING: if you need to run this script multiple times, only do this ONCE!\e[0m"
  read -n 1 -p "Process Famedly change log entries, press 'y' or Enter to skip: " input_key
  echo -e "\n"
  if [[ "$input_key" == "y" ]]; then
    echo -e "\e[32m>>>> Adding Famedly changes to CHANGES.md\e[0m"
    echo -e "\e[32m>>>> ONLY RUN THIS ONE TIME\e[0m"
    # Find out how many lines down in CHANGES.md that the previous '# Synapse' entry
    # was. This gives us the line number needed to run the insertion.
    changelog_line_number=$(grep -n "# Synapse" CHANGES.md | awk 'NR==2 {print $1}' FS=":")

    # Shell expansion is stupid when it comes to escaping things. This is a hack to get
    # the new line character into a string that sed will actually interpret that does
    # not interfere with already appended '\' from the git log output. Used at the end
    # to give us the extra line inside the markdown.
    NL=$'\n'
    # Construct the sed command. This is a little messy. sed requires that new lines are
    # a '\' and not a normal ansi '\n'(and it will insert that for us). We need a basic
    # header for the entry and an additional new line at the end(the markdown itself
    # does not care but this makes it easier to find when opening the file directly).
    sed_command="${changelog_line_number} i\### Famedly additions for ${expected_new_version_tag}\n\n"
    sed_command+="${git_log_output}${NL}"

    # That should do it. The changes from our repo that occurred since the last upstream
    # merge(specifically that do not include said merge) should be inserted just above
    # that previous upstream merge(and just underneath the merge we are in the middle
    # of).
    sed -i "${sed_command}" CHANGES.md

    # Amend the last commit(which should be the merge commit itself) to incorporate
    # changes from the changelog just produced
    echo -e "\e[32m>>>> Amending last commit with Famedly changelog entries\e[0m"
    git add CHANGES.md
    git commit --amend --no-edit --allow-empty
  fi
fi

read -n 1 -p "Press 't' to run linting and tests, or any other key to skip: " input_key
echo -e "\n"
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
  echo -e "\e[32m>>>> Testing successful!\e[0m"
fi

read -n 1 -p "Press 'p' to push branch to Github, or any other key to skip: " input_key
echo -e "\n"
if [[ $input_key == "p" ]]; then
  echo -e "\e[32m>>>> pushing release branch\e[0m"
  git push --force -u origin "${release_branch_name}"
  echo "Visit online `https://github.com/famedly/synapse/pull/new/${release_branch_name}`"
  echo "to open a pull request for this release."
else
  echo "Not pushing branch. Run 'git push --force -u origin ${release_branch_name}' when ready"
fi

echo -e "\e[32m>>>> Finished!\e[0m"
echo -e "\e[32m>> Recommend using $expected_new_version_tag as new release_name when running make_release.sh"
