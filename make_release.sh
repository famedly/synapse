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

# Peel off the build number, so we know what version to use
release_version="${release_name%_*}"
release_branch_name="famedly-release/${release_name%.*}"

logical_cores=$([ $(uname) = 'Darwin' ] &&
                       sysctl -n hw.logicalcpu_max ||
                       nproc)

# make sure that there are no unstashed changes hiding. Adding --exit-code will return
# >= 1 if there is any changes or there is no .git folder here
if git diff --exit-code --quiet; then
    echo "Local repo looks clean"
else
    echo "There are live changes that need to be stashed or commited before your branch is reset for release"
    exit 1
fi


git fetch --tags --multiple origin upstream
git checkout master
git reset --hard origin/master

echo -e "\e[34m>>>> rebasing master branch\e[0m"
#git rebase upstream/master
echo -e "\e[34m>>>> running lint and tests...\e[0m"
poetry install --extras all --no-interaction --remove-untracked
poetry run ./scripts-dev/lint.sh
poetry run trial -j"${logical_cores}" tests
echo -e "\e[34m>>>> Success!\e[0m"
git push -f

echo -e "\e[34m>>>> updating release branch\e[0m"
git checkout -B "${release_branch_name}"
git merge --ff-only master
git push -f -u origin "${release_branch_name}"

echo -e "\e[34m>>>> updating release tag\e[0m"
git checkout "${release_version}"
git merge --ff-only master
git tag -f -s -m "${release_name}" "${release_name}"
git push -f origin "${release_name}"
