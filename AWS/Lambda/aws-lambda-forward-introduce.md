# 采集器「AWS-Lambda」配置手册

通过 AWS 中的 Lambda 对 AWS 中的 EventBridge/CloudWatchLogs 数据进行抓取并上报到观测云日志中。

## 配置 EventBridge 

1.打开 EventBridge 控制台，点击规则。

2.点击创建规则，设置规则名称、描述，选择`具有事件模式的规则`。

3.设置需要监听的事件源，如`Amazon 服务事件`或 `EventBridge 合作伙伴事件`，选择需要监听的事件模式。

4.设置合适的目标类型

5.配置标签

6.创建规则
    
## 配置 Lambda

### 使用控制台创建 Lambda 函数

1.打开 Lamba 控制台的函数页面。

2.选择创建函数

3.选择从头开始创作

4.输入函数名称。

5.设置 `运行时` 选项为 `Python 3.10`
 
6.在 Execution Role（执行角色）中，选择 Create a new role with basic Lambda permissions（创建具有基本 Lambda 权限的新角色，具体权限列表请见附录，如已存在可使用最小权限角色可直接使用）。Lambda 创建执行角色，该角色授予函数上载日志到 Amazon CloudWatchlogs 的权限。在您调用函数时，Lambda 函数担任执行角色，并使用该执行角色为Amazon软件开发工具包创建凭证和从事件源读取数据。

7.点击创建函数

8.在 GitHub 中拉取同步代码至下方代码源中，并添加DATAKIT为datakit部署地址，点击`Depoly`

### 配置 Lambda 触发器

1.点击 `添加触发器`

2.设置`选择一个源`为`EventBridge` 或 `CloudWatchLogs`

3.选择需要监听的`规则`/`日志组`，点击添加。

## X. 附录

### 操作所需最小权限

有权在当前区域和 AWS 账户中创建 CloudWatch 日志组，以及创建日志流并将事件放入这些流中，所需权限列表

logs: CreateLogGroup

logs: CreateLogStream

logs: PutLogEvents

lambda: *