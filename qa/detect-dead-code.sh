#!/bin/bash

# Script to check all Python scripts for PEP-8 issues

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

IFS=$'\n'

# list of directories with sources to check
directories=$(cat ${SCRIPT_DIR}/directories.txt)

# list of separate files to check
separate_files=$(cat ${SCRIPT_DIR}/files.txt)

pass=0
fail=0

function prepare_venv() {
    VIRTUALENV="$(which virtualenv)"
    if [ $? -eq 1 ]; then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV="$(which virtualenv-3)"
    fi
    if [ $? -eq 1 ]; then
        # still don't have virtual environment -> use python3 directly
        python3 -m venv venv && source venv/bin/activate && python3 "$(which pip3)" install vulture
    else
        ${VIRTUALENV} -p python3 venv && source venv/bin/activate && python3 "$(which pip3)" install vulture
    fi
}

pushd "${SCRIPT_DIR}/.."

# run the vulture for all files that are provided in $1
function check_files() {
    for source in $1
    do
        echo "$source"
        vulture --min-confidence 90 "$source"
        if [ $? -eq 0 ]
        then
            echo "    Pass"
            let "pass++"
        elif [ $? -eq 2 ]
        then
            echo "    Illegal usage (should not happen)"
            exit 2
        else
            echo "    Fail"
            let "fail++"
        fi
    done
}


echo "----------------------------------------------------"
echo "Checking source files for dead code and unused imports"
echo "in following directories:"
echo "$directories"
echo "----------------------------------------------------"
echo

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

# checks for the whole directories
for directory in $directories
do
    files=$(find "$directory" -path "$directory/venv" -prune -o -name '*.py' -print)

    check_files "$files"
done

echo "----------------------------------------------------"
echo "Checking following source files for dead code and"
echo "unused imports:"
echo "$separate_files"
echo "----------------------------------------------------"
echo

check_files "$separate_files"

popd

if [ $fail -eq 0 ]
then
    echo "All checks passed for $pass source files"
else
    let total=$pass+$fail
    echo "$fail source files out of $total files seems to contain dead code and/or unused imports"
    exit 1
fi

