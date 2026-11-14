"""Gunicorn worker class used by the container entrypoint.

Identical to uvicorn's worker except for the server header. ``server_header``
has to be turned off in the ASGI server's own config: the response-header
middleware cannot remove it, because uvicorn writes ``Server: uvicorn`` after
the application returns, so the header reappeared on every response no matter
what the middleware did.
"""

from uvicorn.workers import UvicornWorker as _UvicornWorker


class UvicornWorker(_UvicornWorker):
    CONFIG_KWARGS = {**_UvicornWorker.CONFIG_KWARGS, "server_header": False}
