import os
import signal
import sys

from waitress import serve as waitress_serve

from openid_server import create_app, logger


def serve() -> None:
    """
    Production entry point of the container image. Listens on all interfaces on PORT (default 8000),
    expecting a reverse proxy in front of it, which terminates TLS and sets the X-Forwarded-* headers.
    """
    app = create_app()

    # As PID 1 in a container, the process ignores SIGTERM (`docker stop`) unless it handles it.
    # waitress catches SystemExit and shuts down, finishing the requests underway.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    logger.info("-----")
    logger.info("Starting Server")

    waitress_serve(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        # The proxy's address within the container network is rarely fixed, so all are trusted by default.
        trusted_proxy=os.environ.get("TRUSTED_PROXY", "*"),
        trusted_proxy_headers="x-forwarded-for x-forwarded-proto x-forwarded-host x-forwarded-port",
        trusted_proxy_count=1,
        clear_untrusted_proxy_headers=True,
    )


if __name__ == "__main__":
    serve()
