from waitress import serve

from openid_server import create_app
from openid_server import logger

app = create_app()

logger.info("-----")
logger.info("Starting Server")

serve(
    app,
    host="127.0.0.1",
    port=5012,
    trusted_proxy="127.0.0.1",
    trusted_proxy_headers="x-forwarded-for x-forwarded-proto x-forwarded-host x-forwarded-port",
    trusted_proxy_count=1,
    clear_untrusted_proxy_headers=True,
)
