class WaltIdError(Exception):
    """
    Custom exception class for handling errors related to WaltId operations.

    This class is used to encapsulate error messages and, optionally, associated
    endpoint information related to operations involving WaltId services.
    """
    def __init__(self, message: str, *, endpoint: str | None = None):
        super().__init__(message)
        self.endpoint = endpoint

class WaltIdHttpError(WaltIdError):
    """
    Represents an HTTP-specific error for interactions with Walt.id.

    This class is used to encapsulate HTTP errors that occur when communicating
    with the Walt.id API. It provides details regarding the HTTP status code,
    the response body associated with the error, and optionally the API endpoint
    where the error occurred.
    """
    def __init__(self, status_code: int, body: str, *, endpoint: str | None = None):
        msg = f"Walt.id HTTP {status_code} on {endpoint or 'unknown endpoint'}: {body}"
        super().__init__(msg, endpoint=endpoint)
        self.status_code = status_code
        self.body = body
