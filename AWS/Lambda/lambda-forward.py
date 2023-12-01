import base64
import gzip
import json
import copy
import time
import datetime
import pprint

import boto3
import re
import urllib
import urllib3
import logging
from io import BytesIO, BufferedReader
from setting import (
    TAGS,
    MULTILINE_LOG_REGEX_PATTERN,
    SOURCE,
    CUSTOM_TAGS,
    SERVICE,
    HOST,
    DATAKIT,
    PORT,
)

logger = logging.getLogger()

if MULTILINE_LOG_REGEX_PATTERN:
    try:
        multiline_regex = re.compile(
            "[\n\r\f]+(?={})".format(MULTILINE_LOG_REGEX_PATTERN)
        )
    except Exception:
        raise Exception(
            "could not compile multiline regex with pattern: {}".format(
                MULTILINE_LOG_REGEX_PATTERN
            )
        )
    multiline_regex_start_pattern = re.compile(
        "^{}".format(MULTILINE_LOG_REGEX_PATTERN)
    )
rds_regex = re.compile("/aws/rds/(instance|cluster)/(?P<host>[^/]+)/(?P<name>[^/]+)")

GOV, CN = "gov", "cn"

HOST_IDENTITY_REGEXP = re.compile(
    r"^arn:aws:sts::.*?:assumed-role\/(?P<role>.*?)/(?P<host>i-([0-9a-f]{8}|[0-9a-f]{17}))$"
)

cloudtrail_regex = re.compile(
    "\d+_CloudTrail(|-Digest)_\w{2}(|-gov|-cn)-\w{4,9}-\d_(|.+)\d{8}T\d{4,6}Z(|.+).json.gz$",
    re.I,
)


def push_dk(data):
    http = urllib3.PoolManager()
    data = json.dumps(data)
    response = http.request("POST", f'{DATAKIT}:{PORT}/v1/write/logging', body=data,
                            headers={'Content-Type': 'application/json'})
    print('dk_code:', response.status)


def to_datakit_data(event):
    data = {
        'measurement': event.get('source'),
        'time': round(time.time()),
        'tags': {
            # 'timestamp': (str(event.get('timestamp', round(time.time()))) + '000000000')
        },
        'fields': {'message': json_dumps(event)},
    }

    for k, v in event.items():
        if isinstance(v, (list, tuple, dict, set)) or k == 'message':
            try:
                data['fields'][k] = json_dumps(v)
            except Exception:
                data['fields'][k] = v
        else:
            data['tags'][k] = str(v)

    # data = ensure_str_fields(data)
    data = remove_blank_values(data)
    return data


def json_dumps_default(v):
    if isinstance(v, datetime.datetime):
        return datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%dT%H:%M:%SZ')

    return pprint.saferepr(v)


def json_dumps(j, **kwargs):
    '''
    序列化JSON数据
    如输入数据已经是str，会反序列化后重新序列化
    '''
    if isinstance(j, str):
        j = json.loads(j)

    return json.dumps(j, sort_keys=True, default=json_dumps_default, **kwargs)


# def ensure_str_fields(data):
#     # 将fields对应的值全部转成 string 类型
#     for k in list(data['fields'].keys()):
#         v = str(data['fields'][k])
#         data['fields'][k] = v
#
#     return data


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


def generate_metadata(context):
    metadata = {
        "sourcecategory": "aws",
        "aws": {
            "function_version": context.function_version,
            "invoked_function_arn": context.invoked_function_arn,
        },
    }
    # Add custom tags here by adding new value with the following format "key1:value1, key2:value2"  - might be subject to modifications
    custom_tags_data = {
        "function_name": context.function_name.lower(),
        "memory_limit_in_mb": context.memory_limit_in_mb,
        # "forwarder_version": context.function_version,
    }

    metadata[CUSTOM_TAGS] = ",".join(
        filter(
            None,
            [
                TAGS,
                ",".join(
                    ["{}:{}".format(k, v) for k, v in custom_tags_data.items()]
                ),
            ],
        )
    )

    return metadata


def lambda_handler(event, context):
    metadata = generate_metadata(context)
    event_type = "unknown"
    try:
        # 找到对应的解析器
        event_type = parse_event_type(event)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Parsed event type: {event_type}")
        if event_type == "s3":
            events = s3_handler(event, context, metadata)
        elif event_type == "awslogs":
            events = awslogs_handler(event, context, metadata)
        # elif event_type == "events":
        #     events = cwevent_handler(event, metadata)
        # elif event_type == "sns":
        #     events = sns_handler(event, metadata)
        # 目前不支持 kinesis
        # elif event_type == "kinesis":
        #     events = kinesis_awslogs_handler(event, context, metadata)
    except Exception as e:
        # Logs through the socket the error
        err_message = "Error parsing the object. Exception: {} for event {}".format(
            str(e), event
        )
        events = [err_message]

    logs = split(transform(enrich(normalize_events(events, metadata))))
    dk_data_list = []
    for log in logs:
        dk_data = to_datakit_data(log)
        dk_data_list.append(dk_data)
    push_dk(dk_data_list)


def convert_rule_to_nested_json(rule):
    key = None
    result_obj = {}
    if not isinstance(rule, list):
        if "ruleId" in rule and rule["ruleId"]:
            key = rule.pop("ruleId", None)
            result_obj.update({key: rule})
            return result_obj
    for entry in rule:
        if "ruleId" in entry and entry["ruleId"]:
            key = entry.pop("ruleId", None)
        elif "rateBasedRuleName" in entry and entry["rateBasedRuleName"]:
            key = entry.pop("rateBasedRuleName", None)
        elif "name" in entry and "value" in entry:
            key = entry["name"]
            entry = entry["value"]
        result_obj.update({key: entry})
    return result_obj


def parse_aws_waf_logs(event):
    """Parse out complex arrays of objects in AWS WAF logs

    Attributes to convert:
        httpRequest.headers
        nonTerminatingMatchingRules
        rateBasedRuleList
        ruleGroupList

    This prevents having an unparsable array of objects in the final log.
    """
    if isinstance(event, str):
        try:
            event = json.loads(event)
        except json.JSONDecodeError:
            logger.debug("Argument provided for waf parser is not valid JSON")
            return event
    if event.get(SOURCE) != "waf":
        return event

    event_copy = copy.deepcopy(event)

    message = event_copy.get("message", {})
    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            logger.debug("Failed to decode waf message")
            return event

    headers = message.get("httpRequest", {}).get("headers")
    if headers:
        message["httpRequest"]["headers"] = convert_rule_to_nested_json(headers)

    # Iterate through rules in ruleGroupList and nest them under the group id
    # ruleGroupList has three attributes that need to be handled separately
    rule_groups = message.get("ruleGroupList", {})
    if rule_groups and isinstance(rule_groups, list):
        message["ruleGroupList"] = {}
        for rule_group in rule_groups:
            group_id = None
            if "ruleGroupId" in rule_group and rule_group["ruleGroupId"]:
                group_id = rule_group.pop("ruleGroupId", None)
            if group_id not in message["ruleGroupList"]:
                message["ruleGroupList"][group_id] = {}

            # Extract the terminating rule and nest it under its own id
            if "terminatingRule" in rule_group and rule_group["terminatingRule"]:
                terminating_rule = rule_group.pop("terminatingRule", None)
                if not "terminatingRule" in message["ruleGroupList"][group_id]:
                    message["ruleGroupList"][group_id]["terminatingRule"] = {}
                message["ruleGroupList"][group_id]["terminatingRule"].update(
                    convert_rule_to_nested_json(terminating_rule)
                )

            # Iterate through array of non-terminating rules and nest each under its own id
            if "nonTerminatingMatchingRules" in rule_group and isinstance(
                    rule_group["nonTerminatingMatchingRules"], list
            ):
                non_terminating_rules = rule_group.pop(
                    "nonTerminatingMatchingRules", None
                )
                if (
                        "nonTerminatingMatchingRules"
                        not in message["ruleGroupList"][group_id]
                ):
                    message["ruleGroupList"][group_id][
                        "nonTerminatingMatchingRules"
                    ] = {}
                message["ruleGroupList"][group_id][
                    "nonTerminatingMatchingRules"
                ].update(convert_rule_to_nested_json(non_terminating_rules))

            # Iterate through array of excluded rules and nest each under its own id
            if "excludedRules" in rule_group and isinstance(
                    rule_group["excludedRules"], list
            ):
                excluded_rules = rule_group.pop("excludedRules", None)
                if "excludedRules" not in message["ruleGroupList"][group_id]:
                    message["ruleGroupList"][group_id]["excludedRules"] = {}
                message["ruleGroupList"][group_id]["excludedRules"].update(
                    convert_rule_to_nested_json(excluded_rules)
                )

    rate_based_rules = message.get("rateBasedRuleList", {})
    if rate_based_rules:
        message["rateBasedRuleList"] = convert_rule_to_nested_json(rate_based_rules)

    non_terminating_rules = message.get("nonTerminatingMatchingRules", {})
    if non_terminating_rules:
        message["nonTerminatingMatchingRules"] = convert_rule_to_nested_json(
            non_terminating_rules
        )

    event_copy["message"] = message
    return event_copy


def separate_security_hub_findings(event):
    """Replace Security Hub event with series of events based on findings

    Each event should contain one finding only.
    This prevents having an unparsable array of objects in the final log.
    """
    if event.get(SOURCE) != "securityhub" or not event.get("detail", {}).get(
            "findings"
    ):
        return None
    events = []
    event_copy = copy.deepcopy(event)
    # Copy findings before separating
    findings = event_copy.get("detail", {}).get("findings")
    if findings:
        # Remove findings from the original event once we have a copy
        del event_copy["detail"]["findings"]
        # For each finding create a separate log event
        for index, item in enumerate(findings):
            # Copy the original event with source and other metadata
            new_event = copy.deepcopy(event_copy)
            current_finding = findings[index]
            # Get the resources array from the current finding
            resources = current_finding.get("Resources", {})
            new_event["detail"]["finding"] = current_finding
            new_event["detail"]["finding"]["resources"] = {}
            # Separate objects in resources array into distinct attributes
            if resources:
                # Remove from current finding once we have a copy
                del current_finding["Resources"]
                for item in resources:
                    current_resource = item
                    # Capture the type and use it as the distinguishing key
                    resource_type = current_resource.get("Type", {})
                    del current_resource["Type"]
                    new_event["detail"]["finding"]["resources"][
                        resource_type
                    ] = current_resource
            events.append(new_event)
    return events


def parse_lambda_tags_from_arn(arn):
    """Generate the list of lambda tags based on the data in the arn

    Args:
        arn (str): Lambda ARN.
            ex: arn:aws:lambda:us-east-1:172597598159:function:my-lambda[:optional-version]
    """
    # Cap the number of times to split
    split_arn = arn.split(":")

    # If ARN includes version / alias at the end, drop it
    if len(split_arn) > 7:
        split_arn = split_arn[:7]

    _, _, _, region, account_id, _, function_name = split_arn

    return [
        "region:{}".format(region),
        "account_id:{}".format(account_id),
        # Include the aws_account tag to match the aws.lambda CloudWatch metrics
        "aws_account:{}".format(account_id),
        "functionname:{}".format(function_name),
    ]


def get_enriched_lambda_log_tags(log_event):
    """Retrieves extra tags from lambda, either read from the function arn, or by fetching lambda tags from the function itself.

    Args:
        log (dict<str, str | dict | int>): a log parsed from the event in the split method
    """
    # Note that this arn attribute has been lowercased already
    log_function_arn = log_event.get("lambda", {}).get("arn")

    if not log_function_arn:
        return []
    tags_from_arn = parse_lambda_tags_from_arn(log_function_arn)
    # lambda_custom_tags = account_lambda_custom_tags_cache.get(log_function_arn)

    # Combine and dedup tags
    # tags = list(set(tags_from_arn + lambda_custom_tags))
    tags = list(set(tags_from_arn))
    return tags


def add_metadata_to_lambda_log(event):
    """Mutate log dict to add tags, host, and service metadata

    * tags for functionname, aws_account, region
    * host from the Lambda ARN
    * service from the Lambda name

    If the event arg is not a Lambda log then this returns without doing anything

    Args:
        event (dict): the event we are adding Lambda metadata to
    """
    lambda_log_metadata = event.get("lambda", {})
    lambda_log_arn = lambda_log_metadata.get("arn")

    # Do not mutate the event if it's not from Lambda
    if not lambda_log_arn:
        return

    # Set Lambda ARN to "host"
    event[HOST] = lambda_log_arn

    # Function name is the seventh piece of the ARN
    function_name = lambda_log_arn.split(":")[6]
    tags = [f"functionname:{function_name}"]

    # Get custom tags of the Lambda function
    custom_lambda_tags = get_enriched_lambda_log_tags(event)

    # Set the `service` tag and metadata field. If the Lambda function is
    # tagged with a `service` tag, use it, otherwise use the function name.
    service_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("service:")),
        f"service:{function_name}",
    )
    tags.append(service_tag)
    event[SERVICE] = service_tag.split(":")[1]

    # Check if one of the Lambda's custom tags is env
    # If an env tag exists, remove the env:none placeholder
    custom_env_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("env:")), None
    )
    if custom_env_tag is not None:
        event[CUSTOM_TAGS] = event[CUSTOM_TAGS].replace("env:none", "")

    tags += custom_lambda_tags

    # Dedup tags, so we don't end up with functionname twice
    tags = list(set(tags))
    tags.sort()  # Keep order deterministic

    event[CUSTOM_TAGS] = ",".join([event[CUSTOM_TAGS]] + tags)


def extract_tags_from_message(event):
    """When the logs intake pipeline detects a `message` field with a
    JSON content, it extracts the content to the top-level. The fields
    of same name from the top-level will be overridden.

    E.g. the application adds some tags to the log, which appear in the
    `message.tags` field, and the forwarder adds some common tags, such
    as `aws_account`, which appear in the top-level `ddtags` field:

    {
        "message": {
            "tags": "mytag:value", # tags added by the application
            ...
        },
        "tags": "env:xxx,aws_account", # tags added by the forwarder
        ...
    }

    Only the custom tags added by the application will be kept.

    We might want to change the intake pipeline to "merge" the conflicting
    fields rather than "overridding" in the future, but for now we should
    extract `message.tags` and merge it with the top-level `tags` field.
    """
    if "message" in event and CUSTOM_TAGS in event["message"]:
        if isinstance(event["message"], dict):
            extracted_tags = event["message"].pop(CUSTOM_TAGS)
        if isinstance(event["message"], str):
            try:
                message_dict = json.loads(event["message"])
                extracted_tags = message_dict.pop(CUSTOM_TAGS)
                event["message"] = json.dumps(message_dict)
            except Exception:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Failed to extract tags from: {event}")
                return
        event[CUSTOM_TAGS] = f"{event[CUSTOM_TAGS]},{extracted_tags}"


def extract_host_from_cloudtrails(event):
    """Extract the hostname from cloudtrail events userIdentity.arn field if it
    matches AWS hostnames.

    In case of s3 events the fields of the event are not encoded in the
    "message" field, but in the event object itself.
    """

    if event is not None and event.get(SOURCE) == "cloudtrail":
        message = event.get("message", {})
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                logger.debug("Failed to decode cloudtrail message")
                return

        # deal with s3 input type events
        if not message:
            message = event

        if isinstance(message, dict):
            arn = message.get("userIdentity", {}).get("arn")
            if arn is not None:
                match = HOST_IDENTITY_REGEXP.match(arn)
                if match is not None:
                    event[HOST] = match.group("host")


def extract_host_from_guardduty(event):
    if event is not None and event.get(SOURCE) == "guardduty":
        host = event.get("detail", {}).get("resource")
        if isinstance(host, dict):
            host = host.get("instanceDetails", {}).get("instanceId")
            if host is not None:
                event[HOST] = host


def extract_host_from_route53(event):
    if event is not None and event.get(SOURCE) == "route53":
        message = event.get("message", {})
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                logger.debug("Failed to decode Route53 message")
                return

        if isinstance(message, dict):
            host = message.get("srcids", {}).get("instance")
            if host is not None:
                event[HOST] = host


def split(events):
    """Split events into metrics, logs, and trace payloads"""
    logs = []
    for event in events:
        logs.append(event)
        if event.get(CUSTOM_TAGS):
            customer_tags_str = event.pop(CUSTOM_TAGS)
            customer_tags_list = customer_tags_str.split(',')
            for tags in customer_tags_list:
                tmp = tags.split(':', 1)
                event[tmp[0]] = tmp[1]
        elif event:
            pass

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            f"Extracted  {len(logs)} logs"
        )

    # return metrics, logs, trace_payloads
    return logs


def transform(events):
    """Performs transformations on complex events

    Ex: handles special cases with nested arrays of JSON objects
    Args:
        events (dict[]): the list of event dicts we want to transform
    """
    for event in reversed(events):
        findings = separate_security_hub_findings(event)
        if findings:
            events.remove(event)
            events.extend(findings)

        waf = parse_aws_waf_logs(event)
        if waf != event:
            events.remove(event)
            events.append(waf)
    return events


def enrich(events):
    """Adds event-specific tags and attributes to each event

    Args:
        events (dict[]): the list of event dicts we want to enrich
    """
    for event in events:
        add_metadata_to_lambda_log(event)
        extract_tags_from_message(event)
        extract_host_from_cloudtrails(event)
        extract_host_from_guardduty(event)
        extract_host_from_route53(event)

    return events


def normalize_events(events, metadata):
    normalized = []
    events_counter = 0

    for event in events:
        events_counter += 1
        if isinstance(event, dict):
            normalized.append(merge_dicts(event, metadata))
        elif isinstance(event, str):
            normalized.append(merge_dicts({"message": event}, metadata))
        else:
            # drop this log
            continue

    return normalized


def parse_event_type(event):
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            return "s3"
        elif "Sns" in event["Records"][0]:
            # it's not uncommon to fan out s3 notifications through SNS,
            # should treat it as an s3 event rather than sns event.
            sns_msg = event["Records"][0]["Sns"]["Message"]
            try:
                sns_msg_dict = json.loads(sns_msg)
                if "Records" in sns_msg_dict and "s3" in sns_msg_dict["Records"][0]:
                    return "s3"
            except Exception:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"No s3 event detected from SNS message: {sns_msg}")
            return "sns"
        elif "kinesis" in event["Records"][0]:
            return "kinesis"

    elif "awslogs" in event:
        return "awslogs"

    elif "detail" in event:
        return "events"
    raise Exception("Event type not supported (see #Event supported section)")


def s3_handler(event, context, metadata):
    s3 = boto3.client("s3")
    # 如果这是SNS消息中携带的S3事件，则提取该事件并覆盖该事件
    if "Sns" in event["Records"][0]:
        event = json.loads(event["Records"][0]["Sns"]["Message"])

    # 从事件中获取对象并显示其内容类型
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])

    source = parse_event_source(event, key)
    if "transit-gateway" in bucket:
        source = "transitgateway"
    # 补充 sorce 字段
    metadata[SOURCE] = source
    # 如果自定义 tag 有 service 字段，会把 service 替换成自定义的 service 对应的 value
    metadata[SERVICE] = get_service_from_tags(metadata)

    # 获取服务的ARN并将其设置为主机名
    hostname = parse_service_arn(source, key, bucket, context)
    if hostname:
        metadata[HOST] = hostname

    # 获取 S3 对象
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response["Body"]
    data = body.read()

    # Decompress data that has a .gz extension or magic header http://www.onicos.com/staff/iz/formats/gzip.html
    if key[-3:] == ".gz" or data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=BytesIO(data)) as decompress_stream:
            data = b"".join(BufferedReader(decompress_stream))

    is_cloudtrail_bucket = False
    if is_cloudtrail(str(key)):
        cloud_trail = json.loads(data)
        if cloud_trail.get("Records") is not None:
            # 解析 cloud trail 的 Records 字段
            is_cloudtrail_bucket = True
            for event in cloud_trail["Records"]:
                # 补充 event 对象 无则补充 有则 pass
                structured_line = merge_dicts(
                    event, {"aws": {"s3": {"bucket": bucket, "key": key}}}
                )
                yield structured_line

    if not is_cloudtrail_bucket:
        # 检查是否使用多行日志正则表达式模式
        # 并确定日志是行分隔还是模式分隔
        data = data.decode("utf-8", errors="ignore")
        if MULTILINE_LOG_REGEX_PATTERN and multiline_regex_start_pattern.match(data):
            split_data = multiline_regex.split(data)
        else:
            if MULTILINE_LOG_REGEX_PATTERN:
                logger.debug(
                    "MULTILINE_LOG_REGEX_PATTERN %s did not match start of file, splitting by line",
                    MULTILINE_LOG_REGEX_PATTERN,
                )
        split_data = data.splitlines()

        # Send lines to Datadog
        for line in split_data:
            # Create structured object and send it
            structured_line = {
                "aws": {"s3": {"bucket": bucket, "key": key}},
                "message": line,
            }
            yield structured_line


def sns_handler(event, metadata):
    data = event
    # Set the source on the log
    metadata[SOURCE] = "sns"

    for ev in data["Records"]:
        # Create structured object and send it
        structured_line = ev
        yield structured_line


def cwevent_handler(event, metadata):
    data = event

    # Set the source on the log
    source = data.get("source", "cloudwatch")
    service = source.split(".")
    if len(service) > 1:
        metadata[SOURCE] = service[1]
    else:
        metadata[SOURCE] = "cloudwatch"

    metadata[SERVICE] = get_service_from_tags(metadata)

    yield data


def merge_dicts(a, b, path=None):
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                raise Exception(
                    "Conflict while merging metadatas and the log entry at %s"
                    % ".".join(path + [str(key)])
                )
        else:
            a[key] = b[key]
    return a


def parse_service_arn(source, key, bucket, context):
    if source == "elb":
        # For ELB logs we parse the filename to extract parameters in order to rebuild the ARN
        # 1. We extract the region from the filename
        # 2. We extract the loadbalancer name and replace the "." by "/" to match the ARN format
        # 3. We extract the id of the loadbalancer
        # 4. We build the arn
        idsplit = key.split("/")
        if not idsplit:
            logger.debug("Invalid service ARN, unable to parse ELB ARN")
            return
        # If there is a prefix on the S3 bucket, remove the prefix before splitting the key
        if idsplit[0] != "AWSLogs":
            try:
                idsplit = idsplit[idsplit.index("AWSLogs"):]
                keysplit = "/".join(idsplit).split("_")
            except ValueError:
                logger.debug("Invalid S3 key, doesn't contain AWSLogs")
                return
        # If no prefix, split the key
        else:
            keysplit = key.split("_")
        if len(keysplit) > 3:
            region = keysplit[2].lower()
            name = keysplit[3]
            elbname = name.replace(".", "/")
            if len(idsplit) > 1:
                idvalue = idsplit[1]
                partition = get_partition_from_region(region)
                return "arn:{}:elasticloadbalancing:{}:{}:loadbalancer/{}".format(
                    partition, region, idvalue, elbname
                )
    if source == "s3":
        # For S3 access logs we use the bucket name to rebuild the arn
        if bucket:
            return "arn:aws:s3:::{}".format(bucket)
    if source == "cloudfront":
        # For Cloudfront logs we need to get the account and distribution id from the lambda arn and the filename
        # 1. We extract the cloudfront id  from the filename
        # 2. We extract the AWS account id from the lambda arn
        # 3. We build the arn
        namesplit = key.split("/")
        if len(namesplit) > 0:
            filename = namesplit[len(namesplit) - 1]
            # (distribution-ID.YYYY-MM-DD-HH.unique-ID.gz)
            filenamesplit = filename.split(".")
            if len(filenamesplit) > 3:
                distributionID = filenamesplit[len(filenamesplit) - 4].lower()
                arn = context.invoked_function_arn
                arnsplit = arn.split(":")
                if len(arnsplit) == 7:
                    awsaccountID = arnsplit[4].lower()
                    return "arn:aws:cloudfront::{}:distribution/{}".format(
                        awsaccountID, distributionID
                    )
    if source == "redshift":
        # For redshift logs we leverage the filename to extract the relevant information
        # 1. We extract the region from the filename
        # 2. We extract the account-id from the filename
        # 3. We extract the name of the cluster
        # 4. We build the arn: arn:aws:redshift:region:account-id:cluster:cluster-name
        namesplit = key.split("/")
        if len(namesplit) == 8:
            region = namesplit[3].lower()
            accountID = namesplit[1].lower()
            filename = namesplit[7]
            filesplit = filename.split("_")
            if len(filesplit) == 6:
                clustername = filesplit[3]
                return "arn:{}:redshift:{}:{}:cluster:{}:".format(
                    get_partition_from_region(region), region, accountID, clustername
                )
    return


def get_partition_from_region(region):
    partition = "aws"
    if region:
        if GOV in region:
            partition = "aws-us-gov"
        elif CN in region:
            partition = "aws-cn"
    return partition


def get_service_from_tags(metadata):
    # 从 custom_tags 获取服务（如果存在）
    tagsplit = metadata[CUSTOM_TAGS].split(",")
    for tag in tagsplit:
        if tag.startswith("service:"):
            return tag[8:]

    # Default service to source value
    return metadata[SOURCE]


def awslogs_handler(event, context, metadata):
    # Get logs
    with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(event["awslogs"]["data"]))
    ) as decompress_stream:
        # Reading line by line avoid a bug where gzip would take a very long
        # time (>5min) for file around 60MB gzipped
        data = b"".join(BufferedReader(decompress_stream))
    logs = json.loads(data)
    # Set the source on the logs
    source = logs.get("logGroup", "cloudwatch")

    # Use the logStream to identify if this is a CloudTrail event
    # i.e. 123456779121_CloudTrail_us-east-1
    if "_CloudTrail_" in logs["logStream"]:
        source = "cloudtrail"
    if "tgw-attach" in logs["logStream"]:
        source = "transitgateway"
    metadata[SOURCE] = parse_event_source(event, source)

    # Build aws attributes
    aws_attributes = {
        "aws": {
            "awslogs": {
                "logGroup": logs["logGroup"],
                "logStream": logs["logStream"],
                "owner": logs["owner"],
            }
        }
    }

    # Set service from custom tags, which may include the tags set on the log group
    metadata[SERVICE] = get_service_from_tags(metadata)

    # Set host as log group where cloudwatch is source
    if metadata[SOURCE] == "cloudwatch" or metadata.get(HOST, None) == None:
        metadata[HOST] = aws_attributes["aws"]["awslogs"]["logGroup"]

    if metadata[SOURCE] == "appsync":
        metadata[HOST] = aws_attributes["aws"]["awslogs"]["logGroup"].split("/")[-1]

    if metadata[SOURCE] == "verified-access":
        try:
            message = json.loads(logs["logEvents"][0]["message"])
            metadata[HOST] = message["http_request"]["url"]["hostname"]
        except Exception as e:
            logger.debug("Unable to set verified-access log host: %s" % e)

    if metadata[SOURCE] == "stepfunction" and logs["logStream"].startswith(
            "states/"
    ):
        state_machine_arn = ""
        try:
            message = json.loads(logs["logEvents"][0]["message"])
            if message.get("execution_arn") is not None:
                execution_arn = message["execution_arn"]
                arn_tokens = execution_arn.split(":")
                arn_tokens[5] = "stateMachine"
                metadata[HOST] = ":".join(arn_tokens[:-1])
                state_machine_arn = ":".join(arn_tokens[:7])
        except Exception as e:
            logger.debug(
                "Unable to set stepfunction host or get state_machine_arn: %s" % e
            )
    # When parsing rds logs, use the cloudwatch log group name to derive the
    # rds instance name, and add the log name of the stream ingested
    if metadata[SOURCE] in ["rds", "mariadb", "mysql", "postgresql"]:
        match = rds_regex.match(logs["logGroup"])
        if match is not None:
            metadata[HOST] = match.group("host")
            metadata[CUSTOM_TAGS] = (
                    metadata[CUSTOM_TAGS] + ",logname:" + match.group("name")
            )

    # For Lambda logs we want to extract the function name,
    # then rebuild the arn of the monitored lambda using that name.
    # Start by splitting the log group to get the function name
    if metadata[SOURCE] == "lambda":
        log_group_parts = logs["logGroup"].split("/lambda/")
        if len(log_group_parts) > 1:
            lowercase_function_name = log_group_parts[1].lower()
            # Split the arn of the forwarder to extract the prefix
            arn_parts = context.invoked_function_arn.split("function:")
            if len(arn_parts) > 0:
                arn_prefix = arn_parts[0]
                # Rebuild the arn with the lowercased function name
                lowercase_arn = arn_prefix + "function:" + lowercase_function_name
                # Add the lowercased arn as a log attribute
                arn_attributes = {"lambda": {"arn": lowercase_arn}}
                aws_attributes = merge_dicts(aws_attributes, arn_attributes)

                env_tag_exists = (
                        metadata[CUSTOM_TAGS].startswith("env:")
                        or ",env:" in metadata[CUSTOM_TAGS]
                )
                # If there is no env specified, default to env:none
                if not env_tag_exists:
                    metadata[CUSTOM_TAGS] += ",env:none"

    # The EKS log group contains various sources from the K8S control plane.
    # In order to have these automatically trigger the correct pipelines they
    # need to send their events with the correct log source.
    if metadata[SOURCE] == "eks":
        if logs["logStream"].startswith("kube-apiserver-audit-"):
            metadata[SOURCE] = "kubernetes.audit"
        elif logs["logStream"].startswith("kube-scheduler-"):
            metadata[SOURCE] = "kube_scheduler"
        elif logs["logStream"].startswith("kube-apiserver-"):
            metadata[SOURCE] = "kube-apiserver"
        elif logs["logStream"].startswith("kube-controller-manager-"):
            metadata[SOURCE] = "kube-controller-manager"
        elif logs["logStream"].startswith("authenticator-"):
            metadata[SOURCE] = "aws-iam-authenticator"
        # In case the conditions above don't match we maintain eks as the source

    # Create and send structured logs to Datadog
    for log in logs["logEvents"]:
        yield merge_dicts(log, aws_attributes)


def parse_event_source(event, key):
    """解析日志
    Args：
        event（dict）：触发转发器的AWS格式日志事件
        key（string）：如果事件来自S3，则为S3对象键；如果事件来自CW日志，则为
    """
    lowercase_key = str(key).lower()

    # 确定密钥是否与Cloudwatch日志的任何已知源匹配
    if "awslogs" in event:
        return find_cloudwatch_source(lowercase_key)

    # Determines if the key matches any known sources for S3 logs
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            if is_cloudtrail(str(key)):
                return "cloudtrail"

            return find_s3_source(lowercase_key)

    return "aws"


def is_cloudtrail(key):
    match = cloudtrail_regex.search(key)
    return bool(match)


def find_cloudwatch_source(log_group):
    # e.g. /aws/rds/instance/my-mariadb/error
    if log_group.startswith("/aws/rds"):
        for engine in ["mariadb", "mysql", "postgresql"]:
            if engine in log_group:
                return engine
        return "rds"

    if log_group.startswith(
            (
                    # default location for rest api execution logs
                    "api-gateway",  # e.g. Api-Gateway-Execution-Logs_xxxxxx/dev
                    # default location set by serverless framework for rest api access logs
                    "/aws/api-gateway",  # e.g. /aws/api-gateway/my-project
                    # default location set by serverless framework for http api logs
                    "/aws/http-api",  # e.g. /aws/http-api/my-project
            )
    ):
        return "apigateway"

    if log_group.startswith("/aws/vendedlogs/states"):
        return "stepfunction"

    # e.g. dms-tasks-test-instance
    if log_group.startswith("dms-tasks"):
        return "dms"

    # e.g. sns/us-east-1/123456779121/SnsTopicX
    if log_group.startswith("sns/"):
        return "sns"

    # e.g. /aws/fsx/windows/xxx
    if log_group.startswith("/aws/fsx/windows"):
        return "aws.fsx"

    if log_group.startswith("/aws/appsync/"):
        return "appsync"

    for source in [
        "/aws/lambda",  # e.g. /aws/lambda/helloDatadog
        "/aws/codebuild",  # e.g. /aws/codebuild/my-project
        "/aws/kinesis",  # e.g. /aws/kinesisfirehose/dev
        "/aws/docdb",  # e.g. /aws/docdb/yourClusterName/profile
        "/aws/eks",  # e.g. /aws/eks/yourClusterName/profile
    ]:
        if log_group.startswith(source):
            return source.replace("/aws/", "")

    # the below substrings must be in your log group to be detected
    for source in [
        "network-firewall",
        "route53",
        "vpc",
        "fargate",
        "cloudtrail",
        "msk",
        "elasticsearch",
        "transitgateway",
        "verified-access",
    ]:
        if source in log_group:
            return source

    return "cloudwatch"


def find_s3_source(key):
    # e.g. AWSLogs/123456779121/elasticloadbalancing/us-east-1/2020/10/02/123456779121_elasticloadbalancing_us-east-1_app.alb.xxxxx.xx.xxx.xxx_x.log.gz
    if "elasticloadbalancing" in key:
        return "elb"

    # e.g. AWSLogs/123456779121/vpcflowlogs/us-east-1/2020/10/02/123456779121_vpcflowlogs_us-east-1_fl-xxxxx.log.gz
    if "vpcflowlogs" in key:
        return "vpc"

    # e.g. AWSLogs/123456779121/vpcdnsquerylogs/vpc-********/2021/05/11/vpc-********_vpcdnsquerylogs_********_20210511T0910Z_71584702.log.gz
    if "vpcdnsquerylogs" in key:
        return "route53"

    # e.g. 2020/10/02/21/aws-waf-logs-testing-1-2020-10-02-21-25-30-x123x-x456x or AWSLogs/123456779121/WAFLogs/us-east-1/xxxxxx-waf/2022/10/11/14/10/123456779121_waflogs_us-east-1_xxxxx-waf_20221011T1410Z_12756524.log.gz
    if "aws-waf-logs" in key or "waflogs" in key:
        return "waf"

    # e.g. AWSLogs/123456779121/redshift/us-east-1/2020/10/21/123456779121_redshift_us-east-1_mycluster_userlog_2020-10-21T18:01.gz
    if "_redshift_" in key:
        return "redshift"

    # this substring must be in your target prefix to be detected
    if "amazon_documentdb" in key:
        return "docdb"

    # e.g. carbon-black-cloud-forwarder/alerts/org_key=*****/year=2021/month=7/day=19/hour=18/minute=15/second=41/8436e850-7e78-40e4-b3cd-6ebbc854d0a2.jsonl.gz
    if "carbon-black" in key:
        return "carbonblack"

    # the below substrings must be in your target prefix to be detected
    for source in [
        "amazon_codebuild",
        "amazon_kinesis",
        "amazon_dms",
        "amazon_msk",
        "network-firewall",
        "cloudfront",
        "verified-access",
    ]:
        if source in key:
            return source.replace("amazon_", "")

    return "s3"
