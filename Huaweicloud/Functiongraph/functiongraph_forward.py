import time
import json
import urllib3
import base64
import os
import urllib
import obs


class MyEncoder(json.JSONEncoder):

    def default(self, obj):
        """
        判断是否为bytes类型的数据是的话转换成str
        :param obj:
        :return:
        """
        if isinstance(obj, bytes):
            return str(obj, encoding='utf-8')
        return json.JSONEncoder.default(self, obj)


def get_env_var(envvar, default, boolean=False):
    """
    读取环境变量
    """
    value = os.getenv(envvar, default=default)
    if boolean:
        value = value.lower() == "true"
    return value


DATAKIT_IP = get_env_var("DATAKIT_IP", "")
DATAKIT_PORT = get_env_var("DATAKIT_PORT", 9529)


def push_dk(data):
    http = urllib3.PoolManager()
    data = json.dumps(data)
    response = http.request("POST", f'{DATAKIT_IP}:{DATAKIT_PORT}/v1/write/logging', body=data,
                            headers={'Content-Type': 'application/json'})
    print('dk_response_code:', response.status)


def to_datakit_data(event, event_type):
    tags = {}
    for k, v in event.items():
        if k in ['time', 'message']:
            continue
        elif isinstance(v, bytes):
            tags[k] = v.decode()
            continue

        tags[k] = json.dumps(v)
    data = {
        'measurement': event_type,
        'time': round(time.time()),
        'tags': tags,
        'fields': {'message': json.dumps(event, ensure_ascii=False, cls=MyEncoder)},
    }
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
            events = s3_handler(event, context)
        elif event_type == "lts":
            events = lts_handler(event, context)
        else:
            events = [{'message': event}]

    except Exception as e:
        err_message = "Error parsing the object. Exception: {} for event {}".format(
            str(e), event
        )
        events = [err_message]

    if isinstance(events, dict):
        events = [events]

    dk_data_list = []
    for event_data in events:
        data = to_datakit_data(event_data, event_type)
        dk_data_list.append(data)
    push_dk(dk_data_list)  # 上报给第三方数据