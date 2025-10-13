# 采集器「HuaweiCloud-FunctionGraph」配置手册

通过 华为云 中的 FunctionGraph 对 华为云 中的 LTS、OBS 日志数据进行抓取并上报到可观测性平台日志中。

## 配置 FunctionGraph

### 使用控制台创建 FunctionGraph 函数，例如触发器为 LTS


1.打开 FunctionGraph 控制台的函数页面。

2.选择创建函数

3.选择事件函数

4.输入函数名称。

5.设置 `运行时` 选项为 `Python 3.9`

6.在委托名称设置中选择LTS权限的委托。如果没有，可以点击创建委托，委托类型选择云服务/函数工作流 FunctionGraph，同时在授权记录中选择LTS的相关权限。

7.点击创建函数

8.将 Huaweicloud/Functiongraph 目录下的所有脚本复制到代码源中，添加环境变量，指定上报数据源：

    1. DATAKIT_IP: datakit 部署的 ip 地址，上报数据源为 datakit
    2. DATAKIT_PORT: datakit 服务端口，上报数据源为 datakit
    3. DATAWAY_URL: dataway URL (Eg: https://xx-openway.xxx.com) 上报数据源为 dataway
    4. WORKSPACE_TOKEN: 工作空间 `Token`，上报数据源为 dataway

    **注意：上报数据源 datakit 与 dataway 必选一个，选择 datakit 请配置`DATAKIT_IP`， 选择 dataway 请配置`DATAWAY_URL`、`WORKSPACE_TOKEN`**

1. 如果上报数据使用 datakit，且 datakit 端口不是默认的 `9529` 可添加环境变量 DATAKIT_PORT 填写为正确的端口

10.点击 `添加触发器`

11.设置`触发器类型`为`云日志服务 (LTS)` 

12.选择需要监听的`日志组`，点击添加。

## X. 附录

### 操作所需最小权限

有权在当前区域和 华为云 账户中创建 LTS 日志组，以及创建日志流并将事件放入这些流中，所需权限列表

```
lts:*:get
lts:*:list
functiongraph:*:*
```
有权在当前区域和 华为云 账户中创建 LTS 日志组，以及创建日志流并将事件放入这些流中，所需权限列表

```
functiongraph:*:*
obs:object:GetObject"
```