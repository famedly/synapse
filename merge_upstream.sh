#!/bin/bash

set -e

# For a given argument that is a release version, it will be the tag. For now, want the
# format of `vX.Y.Z_A`. The underscore and `A` is important to include, as that is our
# patch version that is separate from the upstream patch version
release_name=$1
echo "release_name ${release_name}"

# The minor number of the version, so of the release_name above which looks like `vX.Y`,
# we are peeling off the `Y` for further use
expected_minor=${release_name##*.}
echo "expected_minor ${expected_minor}"

# What our branch name will be. Upstream uses the format of `release-vX.Y` so to avoid
# confusion we will pre-pend 'famedly' to that and use a `/` to namespace it. Like this:
# `famedly-release/vX.Y`. We do want patch levels and hotfixes to live on the same
# branch as the release major.minor
release_branch_name="famedly-release/${release_name}"
echo "release_branch_name ${release_branch_name}"

upstream_release_branch_name="release-${release_name}"
echo "upstream_release_branch_name ${upstream_release_branch_name}"

logical_cores=$([ $(uname) = 'Darwin' ] &&
                       sysctl -n hw.logicalcpu_max ||
                       nproc)

if [ -z "${release_name}" ]; then
    echo "Usage: $0 <release_name>"
    exit 1
fi

if [ "${release_name}" = "-h" ]; then
    echo "Usage: $0 <release_name>"
    exit 0
fi

echo -e "\e[32m>>>> fetching origin branches\e[0m"
# If the release_name that was passed already exists as a tag, this will fatal error.
# Make sure it does not legitimately exist, or that you really mean to replace it before
# running `git tag -d <release_name>` to remove that one single tag
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
if ! git switch --quiet "$release_branch_name"; then
  echo "branch did not exist, creating"
  # -c creates the branch at our current checkout. Which should be a clean checkout of
  # the master branch from a moment ago
  git switch -c "$release_branch_name"
fi
# Have to re-enable error catching in case something else breaks
set -e

# Fetch existing tags on this branch. If this was a new branch from main, ours will be the
# last tag added. If this was an existing branch we are appending to, ours will still be
# the last tag added.
last_tag_on_this_branch=$(git describe --tags --abbrev=0)
echo "last_tag_on_this_branch $last_tag_on_this_branch"

# Our patch level version, everything after the `_`
famedly_patch_level=${last_tag_on_this_branch#*_}
echo "famedly_patch_level ${famedly_patch_level}"

# The major, minor and patch level, so `vX.Y.Z`
long_ver=${last_tag_on_this_branch%_*}
echo "long_ver ${long_ver}"

# Just the patch level integer, so `Z`
patch_level=${long_ver##*.}
echo "patch_level $patch_level"

# The `vX.Y`
major_minor=${long_ver%.*}
echo "major_minor $major_minor"

# and just the `Y`
minor_ver=${major_minor##*.}
echo "minor_ver $minor_ver"


# First determine if the upstream branch has incremented it's patch level
upstreams_last_tag=$(git ls-remote --tags upstream "$release_name"* | grep -o 'refs/tags/v[0-9]*\.[0-9]*\.[0-9]*' | sort -rV | head -n1 | cut --delimiter='/' --fields=3)
echo "upstreams_last_tag $upstreams_last_tag"
upstream_patch_level=${upstreams_last_tag##*.}
echo "upstream_patch_level $upstream_patch_level"
upstream_major_minor=${upstreams_last_tag%.*}
echo "upstream_major_minor $upstream_major_minor"
upstream_minor_ver=${upstream_major_minor##.*}

# if upstream patch level has increased, we bump ours too
if [[ "$expected_minor" != "$minor_ver" ]]; then
  # must have been a version bump which means this is a new minor version release. In this case, it's likely that it is the same as what upstream's is
  expected_new_version_tag="${upstreams_last_tag}_1"
  echo -e "Likely new release minor version $expected_new_version_tag"

elif [[ "$upstream_patch_level" -gt "$patch_level" ]]; then
  # no minor version bump but there was a patch level version bump, increment our expected patch level
  expected_new_version_tag="${upstreams_last_tag}_1"
  echo -e "Likely new release patch version $expected_new_version_tag"

else
  # no minor and no patch level increase, this is probably just a famedly patch level increase
  increment_patch_level=$(( famedly_patch_level + 1))
  expected_new_version_tag="${upstreams_last_tag}_$increment_patch_level"
  echo -e "Likely new famedly release patch version $expected_new_version_tag"

fi

echo -e "\e[32m>>>> merging master into release branch\e[0m"
# We let this error if there was a merge conflict that needs to be resolved. It should
# be an idempotent process of just rerunning the script to continue on. After a
# `git merge --continue`, of course
git merge "upstream/release-${release_name}" -m "Famedly ${release_name}"


# Retrieve the git log entries themselves and format them to fit well into the
# markdown format. If there were none, we can skip this whole next section
git_log_output=$(git log $(git describe --tags --abbrev=0)..master --pretty=format:'- %s %C(bold blue)(%an)%Creset\' --no-merges --no-decorate | sort -u -f -k2)

if [[ ! -z $git_log_output ]]; then
  echo -e "\e[32m>>>> Listing changes from main branch since last release\e[0m"
  # Find out how many lines down in CHANGES.md that the previous '# Synapse' entry
  # was. This gives us the line number needed to run the insertion.
  changelog_line_number=$(grep -n "# Synapse" CHANGES.md | awk 'NR==2 {print $1}' FS=":")

  # Shell expansion is stupid when it comes to escaping things. This is a hack to get the
  # new line character into a string that sed will actually interpret that does not
  # interfere with already appended '\' from the git log output. Used at the end to give
  # us the extra line inside the markdown.
  NL=$'\n'
  # Construct the sed command. This is a little messy. sed requires that new lines are a
  # '\' and not a normal ansi '\n'(and it will insert that for us). We need a basic header
  # for the entry and an additional new line at the end(the markdown itself does not care
  # but this makes it easier to find when opening the file directly).
  sed_command="${changelog_line_number} i\### Famedly additions for ${expected_new_version_tag}\n\n"
  sed_command+="${git_log_output}${NL}"

  # That should do it. The changes from our repo that occurred since the last upstream
  # merge(specifically that do not include said merge) should be inserted just above that
  # previous upstream merge(and just underneath the merge we are in the middle of).
  # Nice little bonus, they are printed in the console for us to see as the script runs
  sed -i "${sed_command}" CHANGES.md

  # Amend the last commit(which should be the merge commit itself) to incorporate changes
  # from the changelog just produced
  git add CHANGES.md
  git commit --amend --no-edit --allow-empty
fi
#echo "Check any changes or adjustments that need to be made, then"
#read -n 1 -s -r -p "Press any key to continue merge..."

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
  #poetry check
  #poetry install --extras all --no-interaction
  #poetry run ./scripts-dev/lint.sh
  #poetry run trial -j"${logical_cores}" tests
  echo -e "\e[32m>>>> Success!\e[0m"
fi

read -n 1 -p "Press 't' to create tag and push to Github, or any other key to skip\n" input_key
if [[ $input_key == "t" ]]; then
  echo -e "\e[32m>>>> updating release tag\e[0m"
  git tag -f -s -m "${expected_new_version_tag}" "${expected_new_version_tag}"
#  git push -f origin "${expected_new_version_tag}"
fi
echo -e "\e[32m>>>> Finished!\e[0m"
