"""Check if the installed Python interpreter has correct version.

This script has to be called with two command line arguments:
expected_major_version expected_minor_version

The script then check if actual Python version (major+minor) is
the same or newer than expected version.

Usage:
python check_python_version.py 2.7
python3 check_python_version.py 3.6
python3 check_python_version.py 3.7
etc.
"""

import sys


def get_expected_version(arguments):
    """Get the expected version from arguments provided on command line."""
    if len(arguments) <= 2:
        print("Usage python check_python_version.py major minor\n"
              "      python3 check_python_version.py major minor")
        raise Exception("CLI arguments missing")

    # try to read major version
    try:
        major = int(arguments[1])
    except Exception as e:
        print("Can not parse major version '{}'".format(arguments[1]))
        raise e

    # try to read minor version
    try:
        minor = int(arguments[2])
    except Exception as e:
        print("Can not parse minor version '{}'".format(arguments[2]))
        raise e

    return (major, minor)


def get_actual_version():
    """Get the actual version of Python interpreter."""
    return (sys.version_info.major, sys.version_info.minor)


def compare_versions(actual, expected):
    """Compare Python versions, return the exit code."""
    if actual < expected:
        print("Unsupported version {}.{}".format(actual[0], actual[1]))
        return 1
    else:
        m = "OK: actual Python version {}.{} conforms to expected version {}.{}"
        print(m.format(actual[0], actual[1], expected[0], expected[1]))
        return 0


def main():
    """Entry to the Python version comparator."""
    try:
        actual = get_actual_version()
        expected = get_expected_version(sys.argv)
        exit_code = compare_versions(actual, expected)
        sys.exit(exit_code)
    except Exception:
        sys.exit(2)


if __name__ == "__main__":
    main()
