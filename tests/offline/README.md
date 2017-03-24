Offline test support
====================

Tests marked with `pytest.mark.offline` are able to be run *without* a running
web service.

However, many of them will require access to metadata scan output for
particular components, which can be retrieved using the "cache_examples.py"
script in this directory by running:

    ./cache_examples.py https://<server>/api/v1/analysis

Git is configured to ignore cached scans by default - component scans which are
specifically needed for tests need to be whitelisted in .gitignore in this
directory.
