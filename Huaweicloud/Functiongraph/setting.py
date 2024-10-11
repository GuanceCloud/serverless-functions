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
    """
    使用调试日志记录返回给定环境变量的值。
    当boolean=True时，不区分大小写地将该值解析为布尔值。
    """
    value = os.getenv(envvar, default=default)
    if boolean:
        value = value.lower() == "true"
    return value


GUNACE_NODE_DATAWAY_URL = {
    'default': 'https://openway.guance.com',
    'aws': 'https://aws-openway.guance.com',
    'cn3': 'https://cn3-openway.guance.com',
    'cn4': 'https://cn4-openway.guance.com',
    'cn5': 'https://cn5-openway.guance.com',
    'us1': 'https://us1-openway.guance.com',
    'eu1': 'https://eu1-openway.guance.one',
    'ap1': 'https://ap1-openway.guance.one',
    'cn6': 'https://cn6-openway.guance.one'
}


def get_guance_agent_cli():
    cli = None
    if DATAKIT_IP:
        cli = BaseDataKit(host=DATAKIT_IP, port=DATAKIT_PORT, timeout=HTTP_TIMEOUT)

    elif GUANCE_TOKEN:
        dw_url = DATAWAY_URL or GUNACE_NODE_DATAWAY_URL.get(GUANCE_NODE, timeout=HTTP_TIMEOUT)
        cli = DataWay(url=f'{dw_url}?token={GUANCE_TOKEN}')
    
    if not cli:
        raise Exception("You must configure either environment variable `DATAKIT_IP` or (`GUANCE_NODE`, `GUANCE_TOKEN`)")
    return cli


DATAKIT_IP = get_env_var("DATAKIT_IP", "")
DATAKIT_PORT = get_env_var("DATAKIT_PORT", 9529)
HTTP_TIMEOUT = int(get_env_var("HTTP_TIMEOUT", 5))
DATAWAY_URL = get_env_var('DATAWAY_URL', '')
GUANCE_NODE = get_env_var('GUANCE_NODE', 'default')
GUANCE_TOKEN = get_env_var('GUANCE_TOKEN', '')
GUANCE_AGENT_CLI = get_guance_agent_cli()
