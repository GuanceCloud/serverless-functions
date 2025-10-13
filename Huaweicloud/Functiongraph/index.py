import time
import gzip
import json
import urllib
import base64
import logging
import pprint
from datetime import datetime
from io import BytesIO, BufferedReader

import obs
from setting import AGENT_CLI

logger = logging.getLogger()


def json_dumps_default(v):
    if isinstance(v, datetime.datetime):
        return datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%dT%H:%M:%SZ')
    if isinstance(obj, bytes):
        return str(obj, encoding='utf-8')
    
    return pprint.saferepr(v)


def json_dumps(j, **kwargs):
    if isinstance(j, str):
        j = json.loads(j)

    return json.dumps(j, sort_keys=True, default=json_dumps_default, **kwargs)


def json_dumps_pretty(j, **kwargs):
    return json.dumps(j, sort_keys=True, indent=2, ensure_ascii=False, default=json_dumps_default, **kwargs)


def push_agent_cli(cli, category, data):
    res = cli.write_by_category_many(category, data)
    logger.info(f'--> Response: `{res}`')
    logger.info(f'--> Wrote: {len(data)} {category} points')

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f'--> Top 3 pending data entries: \n{json_dumps_pretty(data[:3])}')


def remove_blank_values(data):
    for k in list(data['tags'].keys()):
        v = data['tags'][k].strip()
        if v == '':
            data['tags'].pop(k)
        else:
            data['tags'][k] = v

    for k in list(data['fields'].keys()):
        v = data['fields'][k]

        if isinstance(v, str):
            v = v.strip()
            if v == '':
                data['fields'].pop(k)
            else:
                data['fields'][k] = v

    return data


def to_obs_point(event, event_type):
    tags = {}
    timestamp = round(time.time() * 1000) # ms
    for k, v in event.items():
        if k == 'message':
            continue

        if k == 'time':
            timestamp = v
            continue

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
    event_data = event['data']
    bucket = event_data['obs']['bucket']['name']
    key = event_data['obs']['object']['key']
    key = urllib.parse.unquote_plus(key)
    region = event_data['eventRegion']

    access_key_id = context.getSecurityAccessKey()
    secret_access_key = context.getSecuritySecretKey()
    secret_token = context.getSecurityToken()

    client = obs.ObsClient(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        server=f'https://obs.{region}.myhuaweicloud.com',
        security_token=secret_token
    )
    response = client.getObject(bucketName=bucket, objectKey=key, loadStreamInMemory=True)
    resp_status = response.status
    if resp_status > 300:
        erro_info = '--> !!! `obs.getObject` response status: {resp_status}, error code: {response.errorCode}, error message: {response.errorMessage}'
        logger.error(erro_info)
        raise Exception(erro_info)

    data = response.body.buffer
    if key[-3:] == ".gz" or data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=BytesIO(data)) as decompress_stream:
            data = b"".join(BufferedReader(decompress_stream))
    
    data = data.decode("utf-8", errors="ignore")
    split_data = data.splitlines()
    
    for line in split_data:
        timestamp = int(time.time())
        log = {
            'message': line,
            'time': timestamp,
            'bucket_name': bucket,
            'object_key': key
        }
        yield log


def lts_handler(event, context):
    encoding_data = event["lts"]["data"]
    data = base64.b64decode(encoding_data.encode('utf-8'))
    text = json.loads(data)
    logs = json.loads(text.get('logs'))
    return logs


def parse_event_type(event):
    if data := event.get('data'):
        if data.get('eventSource').upper() == 'OBS':
            return 'obs'

    elif "lts" in event:
        return "lts"

    raise Exception("Event type not supported (see #Event supported section)")


def handler(event, context):
    event_type = parse_event_type(event)

    logger.info(f'--> Event type: {event_type}')
    if event_type == "obs":
        logs = s3_handler(event, context)
    elif event_type == "lts":
        logs = lts_handler(event, context)
    else:
        logs = []

    if isinstance(logs, dict):
        logs = [logs]

    obs_points = []
    if event_type == 'lts':
        logger.info(f'--> Number of logs in Event: {len(logs)}')

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f'--> Top 3 event log data: \n{json_dumps_pretty(logs[:3])}')

    for log in logs:
        request_id = context.getRequestID()
        function_name = context.getFunctionName()
        log['functiongraph_request_id'] = request_id
        log['functiongraph_function_name'] = function_name
        data = to_obs_point(log, event_type)
        obs_points.append(data)
    push_agent_cli(AGENT_CLI, category='logging', data=obs_points)

