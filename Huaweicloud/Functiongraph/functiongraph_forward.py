# -*- coding:utf-8 -*-
import time
import json
import urllib3
import base64
import gzip


DATAKIT = 'http://xx.xx.xx.xx'

print('Start')

def push_dk(data):
    http = urllib3.PoolManager()
    data = json.dumps(data)
    response = http.request("POST", f'{DATAKIT}:9529/v1/write/logging', body=data, headers={'Content-Type': 'application/json'})
    print('dk_code:', response.status)

def to_datakit_data(event):
    
    data = {
        'measurement': 'function_graph_forwarder',
        'time'  : round(time.time()),
        'tags'  : {
            'log_uid':event.get('log_uid'),
            'timestamp':str(event.get('timestamp', round(time.time())))
        },
        'fields' : {'message':json.dumps(event)},
    }
    return data

def event_encode(event):
    encoding_data = event["lts"]["data"]
    data = base64.b64decode(encoding_data.encode('utf-8')) 
    text = json.loads(data)
    return text

def handler(event, context):
    try:
        event_list = event_encode(event).get('logs')
    except:
        event_list = [{'message':event}]
        print('eventbridge event')
    
    event_list = json.loads(event_list)
    print('event_list_value', len(event_list))
    dk_data_list = []
    for eventdata in event_list:
        data = to_datakit_data(eventdata)
        dk_data_list.append(data)
    print('dk_data_list',dk_data_list)
    push_dk(dk_data_list) #上报给第三方数据

    return