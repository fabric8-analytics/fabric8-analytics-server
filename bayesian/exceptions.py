#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Representation of HTTP error."""
from werkzeug.exceptions import HTTPException


class HTTPError(HTTPException):
    """Representation of HTTP error.

    This is a class that represents an HTTP error that occured somewhere.
    Each blueprint should have a function called `coreapi_http_error_handler`,
    which will accept instance of this class and return a response to its
    liking.

    This error is caught by `@app.errorhandler`, so all of raised HTTPError
    instances will be caught and handled there.
    """

    def __init__(self, status_code, error):
        """Call the superclass constructor and set status code and error attributes."""
        super().__init__(self)
        self.code = status_code
        self.description = error
        self.data = {'error': self.description}
