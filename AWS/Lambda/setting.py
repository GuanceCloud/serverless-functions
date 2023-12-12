import os
import logging

logger = logging.getLogger()


def get_env_var(envvar, default, boolean=False):
    """
    使用调试日志记录返回给定环境变量的值。
    当boolean=True时，不区分大小写地将该值解析为布尔值。
    """
    value = os.getenv(envvar, default=default)
    if boolean:
        value = value.lower() == "true"
    logger.debug(f"{envvar}: {value}")
    return value


MULTILINE_LOG_REGEX_PATTERN = get_env_var(
    "MULTILINE_LOG_REGEX_PATTERN", default=None
)

SERVICE = "service"
HOST = "host"
SOURCE = "source"
CUSTOM_TAGS = "tags"
TAGS = get_env_var("TAGS", "")
DATAKIT_IP = get_env_var("DATAKIT_IP", "")
DATAKIT_PORT = get_env_var("DATAKIT_PORT", 9529)
