#!/bin/bash

set -e

release_name=$1
release_branch_name="release-${release_name%.*}"

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

git fetch --tags --multiple origin upstream
git checkout master
git reset --hard origin/master

echo -e "\e[34m>>>> rebasing master branch\e[0m"
git rebase upstream/master
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
git checkout "${release_name}"
git merge --ff-only master
git tag -f -s -m "${release_name}_1" "${release_name}_1"
git push -f origin "${release_name}_1"
