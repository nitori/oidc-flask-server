import os

from werkzeug.middleware.proxy_fix import ProxyFix

from openid_server import create_app

app = create_app()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=0)

if __name__ == "__main__":
    from openid_server import logger

    logger.info("-----")
    logger.info("Starting Server")

    app.run(
        host=os.environ["FLASK_DEBUG_HOST"],
        port=int(os.environ["FLASK_DEBUG_PORT"]),
        debug=True,
        threaded=False,
        processes=1,
    )
