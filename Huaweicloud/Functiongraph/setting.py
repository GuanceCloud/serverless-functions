import os
import logging
from datakit import BaseDataKit
from dataway import DataWay

logger = logging.getLogger()
logger_level = logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper())
logger.setLevel(logger_level)

stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)

def get_env_var(envvar, default, boolean=False):
    value = os.getenv(envvar, default=default)
    if boolean:
        value = value.lower() == "true"
    return value


def get_agent_cli():
    cli = None
    if DATAKIT_IP:
        cli = BaseDataKit(host=DATAKIT_IP, port=DATAKIT_PORT, timeout=HTTP_TIMEOUT)
    elif DATAWAY_URL and WORKSPACE_TOKEN:
        cli = DataWay(url=f'{DATAWAY_URL}?token={WORKSPACE_TOKEN}', timeout=HTTP_TIMEOUT)
    
    if not cli:
        raise Exception("You must configure either environment variable `DATAKIT_IP` or (`DATAWAY_URL`, `WORKSPACE_TOKEN`)")
    return cli


DATAKIT_IP = get_env_var("DATAKIT_IP", "")
DATAKIT_PORT = get_env_var("DATAKIT_PORT", 9529)
HTTP_TIMEOUT = int(get_env_var("HTTP_TIMEOUT", 5))
DATAWAY_URL = get_env_var('DATAWAY_URL', '')
DATAWAY_URL = get_env_var('DATAWAY_URL', '')
WORKSPACE_TOKEN = get_env_var('WORKSPACE_TOKEN', '')
AGENT_CLI = get_agent_cli()

