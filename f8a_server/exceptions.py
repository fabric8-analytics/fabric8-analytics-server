class HTTPError(Exception):
    """This is a class that represents an HTTP error that occured somewhere. Each blueprint
    should have a function called `coreapi_http_error_handler`, which will accept instance
    of this class and return a response to its liking.

    This error is caught by `@app.errorhandler`, so all of raised HTTPError instances will
    be caught and handled there.
    """
    def __init__(self, status_code, error):
        Exception.__init__(self)
        self.status_code = status_code
        self.error = error
