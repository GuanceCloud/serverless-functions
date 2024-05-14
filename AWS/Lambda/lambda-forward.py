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
    GUANCE_AGENT_CLI
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


def push_guance(cli, category, data):
    res = cli.write_by_category_many(category, data)
    logger.info(f'wirte_guance_response:{res}, write {len(data)} data')
    
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f'The first three data:\n{json_dumps_default(data[:3])}')


def to_datakit_data(event):
    data = {
        'measurement': event.get('source'),
        'timestamp': round(time.time()),
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
    # 通过添加以下格式的新值“key1:value1，key2:value2”在此处添加自定义标记-可能会进行修改
    custom_tags_data = {
        "function_name": context.function_name.lower(),
        "memory_limit_in_mb": context.memory_limit_in_mb,
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
        elif event_type == "events":
            events = cwevent_handler(event, metadata)

    except Exception as e:
        err_message = "Error parsing the object. Exception: {} for event {}".format(
            str(e), event
        )
        events = [err_message]

    logs = split(transform(enrich(normalize_events(events, metadata))))
    dk_data_list = []
    for log in logs:
        dk_data = to_datakit_data(log)
        dk_data_list.append(dk_data)
    push_guance(GUANCE_AGENT_CLI, category='logging', data=dk_data_list)


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
    """
    解析出AWS WAF日志中的复杂对象数组

    要转换的属性：

    httpRequest.headers

    非终止匹配规则

    rateBasedRuleList

    ruleGroupList

    这样可以防止在最终日志中出现无法解析的对象数组。
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

    # 遍历ruleGroupList中的规则，并将它们嵌套在组id下
    # ruleGroupList有三个属性需要分别处理
    rule_groups = message.get("ruleGroupList", {})
    if rule_groups and isinstance(rule_groups, list):
        message["ruleGroupList"] = {}
        for rule_group in rule_groups:
            group_id = None
            if "ruleGroupId" in rule_group and rule_group["ruleGroupId"]:
                group_id = rule_group.pop("ruleGroupId", None)
            if group_id not in message["ruleGroupList"]:
                message["ruleGroupList"][group_id] = {}

            # 提取终止规则并将其嵌套在自己的id下
            if "terminatingRule" in rule_group and rule_group["terminatingRule"]:
                terminating_rule = rule_group.pop("terminatingRule", None)
                if not "terminatingRule" in message["ruleGroupList"][group_id]:
                    message["ruleGroupList"][group_id]["terminatingRule"] = {}
                message["ruleGroupList"][group_id]["terminatingRule"].update(
                    convert_rule_to_nested_json(terminating_rule)
                )

            # 遍历非终止规则数组，并将每个规则嵌套在自己的id下
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

            # 遍历排除的规则数组，并将每个规则嵌套在自己的id下
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
    """
    将Security Hub事件替换为基于调查结果的一系列事件

    每个事件应仅包含一个查找。

    这样可以防止在最终日志中出现无法解析的对象数组。
    """
    if event.get(SOURCE) != "securityhub" or not event.get("detail", {}).get(
            "findings"
    ):
        return None
    events = []
    event_copy = copy.deepcopy(event)
    # 分离前复制结果
    findings = event_copy.get("detail", {}).get("findings")
    if findings:
        # 一旦我们有了副本，就从原始事件中删除调查结果
        del event_copy["detail"]["findings"]
        # 为每个查找创建一个单独的日志事件
        for index, item in enumerate(findings):
            # 复制带有源和其他元数据的原始事件
            new_event = copy.deepcopy(event_copy)
            current_finding = findings[index]
            # 从当前查找中获取资源数组
            resources = current_finding.get("Resources", {})
            new_event["detail"]["finding"] = current_finding
            new_event["detail"]["finding"]["resources"] = {}
            # 将资源阵列中的对象分离为不同的属性
            if resources:
                # 一旦我们有了副本，就从当前查找中删除
                del current_finding["Resources"]
                for item in resources:
                    current_resource = item
                    # 捕获类型并将其用作区分键
                    resource_type = current_resource.get("Type", {})
                    del current_resource["Type"]
                    new_event["detail"]["finding"]["resources"][
                        resource_type
                    ] = current_resource
            events.append(new_event)
    return events


def parse_lambda_tags_from_arn(arn):
    """
    基于arn中的数据生成lambda标记的列表
    """
    split_arn = arn.split(":")

    # 如果ARN在末尾包含版本/别名，将其删除
    if len(split_arn) > 7:
        split_arn = split_arn[:7]

    _, _, _, region, account_id, _, function_name = split_arn

    return [
        "region:{}".format(region),
        "account_id:{}".format(account_id),
        "aws_account:{}".format(account_id),
        "functionname:{}".format(function_name),
    ]


def get_enriched_lambda_log_tags(log_event):
    """
    从lambda中检索额外的标记，可以从函数arn读取，也可以从函数本身获取lambda标记。
    """
    # 请注意，此arn属性已被降低了大小写
    log_function_arn = log_event.get("lambda", {}).get("arn")

    if not log_function_arn:
        return []
    tags_from_arn = parse_lambda_tags_from_arn(log_function_arn)
    tags = list(set(tags_from_arn))
    return tags


def add_metadata_to_lambda_log(event):
    """
    更改日志dict以添加标记、主机和服务元数据

        *functionname、aws_account、region的标记

        *Lambda ARN的主机

        *Lambda名称的服务

    如果事件arg不是Lambda日志，则返回时不执行任何操作

    Args：

    event（dict）：我们将Lambda元数据添加到的事件
    """
    lambda_log_metadata = event.get("lambda", {})
    lambda_log_arn = lambda_log_metadata.get("arn")

    # 如果事件不是来自Lambda，请不要对其进行转换
    if not lambda_log_arn:
        return

    event[HOST] = lambda_log_arn

    function_name = lambda_log_arn.split(":")[6]
    tags = [f"functionname:{function_name}"]

    # 获取Lambda函数的自定义标记
    custom_lambda_tags = get_enriched_lambda_log_tags(event)

    service_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("service:")),
        f"service:{function_name}",
    )
    tags.append(service_tag)
    event[SERVICE] = service_tag.split(":")[1]

    custom_env_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("env:")), None
    )
    if custom_env_tag is not None:
        event[CUSTOM_TAGS] = event[CUSTOM_TAGS].replace("env:none", "")

    tags += custom_lambda_tags

    # Dedup标记，这样我们就不会两次使用 function name
    tags = list(set(tags))
    tags.sort()  # 保持订单确定性

    event[CUSTOM_TAGS] = ",".join([event[CUSTOM_TAGS]] + tags)


def extract_tags_from_message(event):
    """
    当日志获取管道检测到带有的“消息”字段时
    JSON内容，它将内容提取到顶层。字段
    顶级中相同名称的将被覆盖。

    例如，应用程序将一些标记添加到日志中，这些标记显示在
    `message.tags'字段，转发器添加一些常见的标记，例如
    作为`aws_account`，出现在顶级`tags'字段中：

    {
        "message": {
            "tags": "mytag:value", # tags added by the application
            ...
        },
        "tags": "env:xxx,aws_account", # tags added by the forwarder
        ...
    }

    只有应用程序添加的自定义标记才会保留。
    但现在我们应该提取 message.tags 并将其与顶级 tags 字段合并。
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
    """
    从cloudtrail events userIdentity.arn 字段中提取主机名，如果

    与 AWS 主机名匹配。
    在 s3 事件的情况下，事件的字段不会编码在
    message 字段，但在事件对象本身中。
    """

    if event is not None and event.get(SOURCE) == "cloudtrail":
        message = event.get("message", {})
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                logger.debug("Failed to decode cloudtrail message")
                return

        # 处理s3输入类型事件
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
    """
    拆分日志 并把 tags 内容提取出到顶层
    """
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

    return logs


def transform(events):
    """
    对复杂事件执行转换，例如：使用JSON对象的嵌套数组处理特殊情况
    Args：
    events（dict[]）：我们要转换的事件dict的列表
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
    """
    向每个事件添加特定于事件的标记和属性

    Args:
        events (dict[]): 丰富的事件列表
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
            continue

    return normalized


def parse_event_type(event):
    """
    判断日志类型
    """
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            return "s3"
        elif "Sns" in event["Records"][0]:
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

        for line in split_data:
            # 创建结构化对象并发送
            structured_line = {
                "aws": {"s3": {"bucket": bucket, "key": key}},
                "message": line,
            }
            yield structured_line


def cwevent_handler(event, metadata):
    data = event

    # Set the source on the log
    source = data.pop("source", "cloudwatch")
    service = source.split(".")
    if len(service) > 1:
        metadata[SOURCE] = service[1]
    else:
        metadata[SOURCE] = "cloudwatch"

    metadata[SERVICE] = get_service_from_tags(metadata)

    yield data


def merge_dicts(a, b, path=None):
    """
    将 b 的内容填充到 a 相同的 key 里面
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass
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
        # 对于ELB日志，解析文件名以提取参数，从而重建ARN
        # 1. 从文件名中提取 region
        # 2. 提取 loadbalancer Name，并将“.”替换为“/”以匹配ARN格式
        # 3. 提取 loadbalancer Id
        # 4. 构建 arn
        idsplit = key.split("/")
        if not idsplit:
            logger.debug("Invalid service ARN, unable to parse ELB ARN")
            return
        # 如果S3存储桶上有前缀，在拆分密钥之前删除前缀
        if idsplit[0] != "AWSLogs":
            try:
                idsplit = idsplit[idsplit.index("AWSLogs"):]
                keysplit = "/".join(idsplit).split("_")
            except ValueError:
                logger.debug("Invalid S3 key, doesn't contain AWSLogs")
                return
        # 如果没有前缀，则拆分密钥
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
        # 对于S3访问日志，使用bucket名称来重建arn
        if bucket:
            return "arn:aws:s3:::{}".format(bucket)
    if source == "cloudfront":
        # 对于Cloudfront日志，我们需要从lambda arn 和文件名中获取 account 和 distribution id
        # 1. 从文件名中提取cloudfront id
        # 2. 从lambda arn中提取AWS帐户id
        # 3. 构建 arn
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
        # 对于 redshift 日志，利用文件名提取相关信息
        # 1. 从文件名中提取 region
        # 2. 从文件名中提取 account-id
        # 3. 提取集群的名称
        # 4. 构建arn:an:aws:redshift:region:account-id:cluster:cluster-name
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
    """
    获取分区
    aws-us-gov｜aws-cn
    """
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

    return metadata[SOURCE]


def awslogs_handler(event, context, metadata):
    # 获取日志
    with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(event["awslogs"]["data"]))
    ) as decompress_stream:
        # 逐行读取可以避免出现gzip需要很长时间的错误
        # 文件大小约为60MB的时间（>5分钟）gzipped
        data = b"".join(BufferedReader(decompress_stream))
    logs = json.loads(data)
    # 在日志上设置源
    source = logs.get("logGroup", "cloudwatch")

    # 使用logStream确定这是否是CloudTrail事件
    if "_CloudTrail_" in logs["logStream"]:
        source = "cloudtrail"
    if "tgw-attach" in logs["logStream"]:
        source = "transitgateway"
    metadata[SOURCE] = parse_event_source(event, source)

    # 构建aws属性
    aws_attributes = {
        "aws": {
            "awslogs": {
                "logGroup": logs["logGroup"],
                "logStream": logs["logStream"],
                "owner": logs["owner"],
            }
        }
    }

    # 从自定义标记设置服务，其中可能包括在日志组上设置的标记
    metadata[SERVICE] = get_service_from_tags(metadata)

    # 将主机设置为cloudwatch所在的日志组
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
    # 在解析rds日志时，使用cloudwatch日志组名称来派生
    # rds实例名称，并添加摄入的流的日志名称
    if metadata[SOURCE] in ["rds", "mariadb", "mysql", "postgresql"]:
        match = rds_regex.match(logs["logGroup"])
        if match is not None:
            metadata[HOST] = match.group("host")
            metadata[CUSTOM_TAGS] = (
                    metadata[CUSTOM_TAGS] + ",logname:" + match.group("name")
            )

    # 对于Lambda日志，提取函数名称
    # 然后使用该名称重新生成受监控lambda的arn。
    # 首先拆分日志组以获取函数名称
    if metadata[SOURCE] == "lambda":
        log_group_parts = logs["logGroup"].split("/lambda/")
        if len(log_group_parts) > 1:
            lowercase_function_name = log_group_parts[1].lower()
            # 拆分转发器的arn以提取前缀
            arn_parts = context.invoked_function_arn.split("function:")
            if len(arn_parts) > 0:
                arn_prefix = arn_parts[0]
                # 使用小写的函数名重新生成arn
                lowercase_arn = arn_prefix + "function:" + lowercase_function_name
                # 将带下划线的arn添加为日志属性
                arn_attributes = {"lambda": {"arn": lowercase_arn}}
                aws_attributes = merge_dicts(aws_attributes, arn_attributes)

                env_tag_exists = (
                        metadata[CUSTOM_TAGS].startswith("env:")
                        or ",env:" in metadata[CUSTOM_TAGS]
                )
                # 如果未指定env，则默认为env:none
                if not env_tag_exists:
                    metadata[CUSTOM_TAGS] += ",env:none"

    # EKS日志组包含来自K8S控制平面的各种源。
    # 为了让这些自动触发正确，他们需要使用正确的日志源发送其事件。
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
        # 如果上述条件不匹配，将eks作为源

    # 创建结构化日志并将其发送
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

    # 确定密钥是否与S3日志的任何已知源匹配
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
    # For Example /aws/rds/instance/my-mariadb/error
    if log_group.startswith("/aws/rds"):
        for engine in ["mariadb", "mysql", "postgresql"]:
            if engine in log_group:
                return engine
        return "rds"

    if log_group.startswith(
            (
                    # rest api执行日志的默认位置
                    "api-gateway",  # For Example Api-Gateway-Execution-Logs_xxxxxx/dev
                    # 无服务器框架为restapi访问日志设置的默认位置
                    "/aws/api-gateway",  # For Example /aws/api-gateway/my-project
                    # 无服务器框架为http api日志设置的默认位置
                    "/aws/http-api",  # For Example /aws/http-api/my-project
            )
    ):
        return "apigateway"

    if log_group.startswith("/aws/vendedlogs/states"):
        return "stepfunction"

    # For Example dms-tasks-test-instance
    if log_group.startswith("dms-tasks"):
        return "dms"

    # For Example sns/us-east-1/123456779121/SnsTopicX
    if log_group.startswith("sns/"):
        return "sns"

    # For Example /aws/fsx/windows/xxx
    if log_group.startswith("/aws/fsx/windows"):
        return "aws.fsx"

    if log_group.startswith("/aws/appsync/"):
        return "appsync"

    for source in [
        "/aws/lambda",  # For Example /aws/lambda/helloTest
        "/aws/codebuild",  # For Example /aws/codebuild/my-project
        "/aws/kinesis",  # For Example /aws/kinesisfirehose/dev
        "/aws/docdb",  # For Example /aws/docdb/yourClusterName/profile
        "/aws/eks",  # For Example /aws/eks/yourClusterName/profile
    ]:
        if log_group.startswith(source):
            return source.replace("/aws/", "")

    # 以下子字符串必须在您的日志组中才能被检测
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
    # For Example AWSLogs/123456779121/elasticloadbalancing/us-east-1/2020/10/02/123456779121_elasticloadbalancing_us-east-1_app.alb.xxxxx.xx.xxx.xxx_x.log.gz
    if "elasticloadbalancing" in key:
        return "elb"

    # For Example AWSLogs/123456779121/vpcflowlogs/us-east-1/2020/10/02/123456779121_vpcflowlogs_us-east-1_fl-xxxxx.log.gz
    if "vpcflowlogs" in key:
        return "vpc"

    # For Example AWSLogs/123456779121/vpcdnsquerylogs/vpc-********/2021/05/11/vpc-********_vpcdnsquerylogs_********_20210511T0910Z_71584702.log.gz
    if "vpcdnsquerylogs" in key:
        return "route53"

    # For Example 2020/10/02/21/aws-waf-logs-testing-1-2020-10-02-21-25-30-x123x-x456x or AWSLogs/123456779121/WAFLogs/us-east-1/xxxxxx-waf/2022/10/11/14/10/123456779121_waflogs_us-east-1_xxxxx-waf_20221011T1410Z_12756524.log.gz
    if "aws-waf-logs" in key or "waflogs" in key:
        return "waf"

    # For Example AWSLogs/123456779121/redshift/us-east-1/2020/10/21/123456779121_redshift_us-east-1_mycluster_userlog_2020-10-21T18:01.gz
    if "_redshift_" in key:
        return "redshift"

    # this substring must be in your target prefix to be detected
    if "amazon_documentdb" in key:
        return "docdb"

    # For Example carbon-black-cloud-forwarder/alerts/org_key=*****/year=2021/month=7/day=19/hour=18/minute=15/second=41/8436e850-7e78-40e4-b3cd-6ebbc854d0a2.jsonl.gz
    if "carbon-black" in key:
        return "carbonblack"

    # 以下子字符串必须位于要检测的目标前缀中
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
