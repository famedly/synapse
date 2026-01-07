#!/bin/bash

set -e

release_name=$1

help_text () {
    echo "Usage: $0 <release_name>"
    echo " <release_name> should be a full format of vX.Y.Z_A, where:"
    echo " X is the major version"
    echo " Y is the minor version"
    echo " Z is the patch version"
    echo " A is the Famedly build number"
}
if ! [[ "${release_name}" =~ ^v[0-9].[0-9]{3,}.[0-9]{1,}_[0-9]{1,}$ ]]; then
    help_text
    exit 0
fi

if [ "${release_name}" = "-h" ]; then
    help_text
    exit 0
fi

# Peel off the build number, so we know what version to use. This will be the tag from
# the upstream repo in the format of vX.Y.Z
upstream_release_version="${release_name%_*}"
release_branch_name="famedly-release/${release_name%.*}"

logical_cores=$([ $(uname) = 'Darwin' ] &&
                       sysctl -n hw.logicalcpu_max ||
                       nproc)

# make sure that there are no un-stashed changes hiding. Adding --exit-code will return
# >= 1 if there is any changes or there is no .git folder here
if git diff --exit-code --quiet; then
    echo "Local checkout looks clean"
else
    echo "There are live changes that need to be stashed or commited before your branch is reset for release"
    exit 1
fi

git fetch --tags --multiple origin upstream
git checkout master
git reset --hard origin/master

echo -e "\e[34m>>>> creating/updating release branch\e[0m"
git checkout -B "${release_branch_name}"
git merge "${upstream_release_version}" -m "Famedly Release ${release_name}"
# If there are merge conflicts, this is where it will error and exit

echo -e "\e[34m>>>> running lint and tests...\e[0m"
poetry install --extras all --no-interaction --remove-untracked
poetry run ./scripts-dev/lint.sh
poetry run trial -j"${logical_cores}" tests
echo -e "\e[34m>>>> tests successful!\e[0m"
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
  git commit -m "Update Changelog"
fi

git push -f -u origin "${release_branch_name}"
echo -e "\e[34m>>>> Go to Github and open the pull request for the release\e[0m"



#echo -e "\e[34m>>>> updating release tag\e[0m"
# This will trigger the docker build
#git checkout "${release_branch_name}"
#git merge --ff-only master
#git tag -f -s -m "${release_name}" "${release_name}"
#git push -f origin "${release_name}"
#
#echo -e "\e[34m>>>> updating master branch\e[0m"
#git checkout master
#git merge "${release_branch_name}"
#git push origin
