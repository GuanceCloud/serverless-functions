import time
import json
import urllib3
import base64
import logging
import pprint
import os
import urllib
import obs
from setting import GUANCE_AGENT_CLI

logger = logging.getLogger()


class MyEncoder(json.JSONEncoder):

    def default(self, obj):
        """
        判断是否为bytes类型的数据是的话转换成str
        :param obj:
        :return:
        """
        if isinstance(obj, bytes):
            return str(obj, encoding='utf-8')

        return pprint.saferepr(obj)


def json_dumps_default(v):
    if isinstance(v, datetime.datetime):
        return datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%dT%H:%M:%SZ')
    if isinstance(obj, bytes):
        return str(obj, encoding='utf-8')
    
    return pprint.saferepr(v)


def json_dumps(j, **kwargs):
    '''
    序列化JSON数据
    如输入数据已经是str，会反序列化后重新序列化
    '''
    if isinstance(j, str):
        j = json.loads(j)

    return json.dumps(j, sort_keys=True, default=json_dumps_default, **kwargs)


def json_dumps_pretty(j, **kwargs):
    '''
    美化方式输出序列化JSON数据
    '''
    return json.dumps(j, sort_keys=True, indent=2, ensure_ascii=False, default=json_dumps_default, **kwargs)


def push_guance(cli, category, data):
    res = cli.write_by_category_many(category, data)
    logger.info(f'--> 响应：`{res}`')
    logger.info(f'--> 写入 {category}: {len(data)}条数据')

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f'--> 实际待写入前3条数据如下: \n{json_dumps_pretty(data[:3])}')


def remove_blank_values(data):
    # 去除tags中的空字符串、空白字符串内容
    for k in list(data['tags'].keys()):
        v = data['tags'][k].strip()
        if v == '':
            data['tags'].pop(k)
        else:
            data['tags'][k] = v

    # 去除fields中的空字符串、空白字符串内容
    for k in list(data['fields'].keys()):
        v = data['fields'][k]

        # 仅在字符串内容时处理
        if isinstance(v, str):
            v = v.strip()
            if v == '':
                data['fields'].pop(k)
            else:
                data['fields'][k] = v

    return data


def to_guance_point(event, event_type):
    tags = {}
    timestamp = round(time.time() * 1000) # ms
    for k, v in event.items():
        if k == 'message':
            continue

        if k == 'time' and event_type == 'lts':
            timestamp = v

        if isinstance(v, (list, tuple, dict, set)):
            tags[k] = json_dumps(v)
            continue

        if isinstance(v, bytes):
            tags[k] = v.decode()
            continue

        tags[k] = str(v)

    message = event.get('message') or event
    if not isinstance(message, str):
        message = json_dumps(message, ensure_ascii=False)

    data = {
        'measurement': event_type,
        'timestamp': timestamp,
        'tags': tags,
        'fields': {'message': message},
    }
    data = remove_blank_values(data)
    return data


def s3_handler(event, context):
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])
    region = event['Records'][0]['awsRegion']

    access_key_id = context.getSecurityAccessKey()
    secret_access_key = context.getSecuritySecretKey()
    secret_token = context.getSecurityToken()

    client = obs.ObsClient(access_key_id=access_key_id, secret_access_key=secret_access_key,
                           server=f'https://obs.{region}.myhuaweicloud.com', security_token=secret_token)
    response = client.getObject(bucketName=bucket, objectKey=key, loadStreamInMemory=True)
    body = response["body"]

    return body


def lts_handler(event, context):
    encoding_data = event["lts"]["data"]
    data = base64.b64decode(encoding_data.encode('utf-8'))
    text = json.loads(data)
    logs = json.loads(text.get('logs'))
    return logs


def parse_event_type(event):
    """
    判断日志类型
    """
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            return "obs"

    elif "lts" in event:
        return "lts"
    raise Exception("Event type not supported (see #Event supported section)")


def handler(event, context):
    event_type = "function_graph_forwarder"
    try:
        # 找到对应的解析器
        event_type = parse_event_type(event)
        if event_type == "obs":
            logs = s3_handler(event, context)
        elif event_type == "lts":
            logs = lts_handler(event, context)
        else:
            logs = []

    except Exception as e:
        err_message = "Error parsing the object. Exception: {} for event {}".format(
            str(e), event
        )
        return

    if isinstance(logs, dict):
        logs = [logs]

    guance_points = []
    logger.info(f'--> Event 中日志条数: {len(logs)}')
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f'--> 前 3 条 log 数据如下: \n{json_dumps_pretty(logs[:3])}')

    for log in logs:
        request_id = context.getRequestID()
        function_name = context.getFunctionName()
        log['functiongraph_request_id'] = request_id
        log['functiongraph_function_name'] = function_name
        data = to_guance_point(log, event_type)
        guance_points.append(data)
    push_guance(GUANCE_AGENT_CLI, category='logging', data=guance_points)

