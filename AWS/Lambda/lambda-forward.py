import time
import json
import urllib3
import base64
import gzip


DATAKIT = 'xxx'

print('Start')

def push_dk(data):
    http = urllib3.PoolManager()
    data = json.dumps(data)
    print('dk_data:', data)
    response = http.request("POST", f'{DATAKIT}:9529/v1/write/logging', body=data, headers={'Content-Type': 'application/json'})
    print('dk_code:', response.status)

def to_datakit_data(event,log_group):
    data = {
        'measurement': 'lambda_forwarder',
        'time'  : time.time_ns(),
        'tags'  : {
            'id':event.get('id'),
            'timestamp':str(event.get('timestamp', round(time.time()))),
            'log_group':log_group
        },
        'fields' : {'message':json.dumps(event)},
    }
    try:
        event_message = json.loads(event.get('message'))
    except:
        return data

    for k, v in event_message.items():
        if isinstance(v, str):
            data['tags'][k] = v
        else:
            data['fields'][k] = v
    return data

def event_encode(event):
    event = event['awslogs']['data']
    event = base64.b64decode(event.encode('utf-8'))
    event = gzip.decompress(event).decode('utf-8')
    event = json.loads(event)
    return event

def lambda_handler(event, context):
    
    try:
        log_group = event_encode(event).get('logGroup')
        event_list = event_encode(event).get('logEvents')
    except:
        event_list = [{'message':event}]
        log_group = ''
        print('eventbridge event')

    dk_data_list = []
    for event in event_list:
        data = to_datakit_data(event,log_group)
        dk_data_list.append(data)
    print('dk_data_list',dk_data_list)
    push_dk(dk_data_list)

    return