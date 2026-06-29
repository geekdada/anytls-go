# AnyTLS

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 快速食用方法

为了方便，示例服务器和客户端默认采用不安全的配置，该配置假设您不会遭遇 TLS 中间人攻击（这种情况偶尔发生在网络接入层，在骨干网络上几乎不可能实现）；否则，您的通信内容可能会被中间人截获。

### 示例服务器

```
./anytls-server -l 0.0.0.0:8443 -p 密码
```

`0.0.0.0:8443` 为服务器监听的地址和端口。

### 示例客户端

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码
```

`127.0.0.1:1080` 为本机 Socks5 代理监听地址，理论上支持 TCP 和 UDP(通过 udp over tcp 传输)。

v0.0.12 版本起，示例客户端可直接使用 URI 格式:

```
./anytls-client -l 127.0.0.1:1080 -s "anytls://password@host:port"
```

### sing-box

https://github.com/SagerNet/sing-box

它包含了 anytls 协议的服务器和客户端。

### mihomo

https://github.com/MetaCubeX/mihomo

它包含了 anytls 协议的服务器和客户端。

### Shadowrocket

Shadowrocket 2.2.65+ 实现了 anytls 协议的客户端。

## 本分支相对上游的改动

本分支在上游 `anytls-go` 的基础上，为**服务端**新增了三个子系统，与 [hysteria 2](https://github.com/apernet/hysteria) 的对应功能保持一致（请求/响应格式、接口路径与副作用均对齐）。客户端与线路协议未作改动，完全向后兼容。

### YAML 配置文件（`-c`）

服务端新增 `-c` 参数指定 YAML 配置文件。命令行参数（`-l`/`-p`/`-padding-scheme`）仅在显式传入时覆盖 YAML 中的对应项。

```yaml
listen: 0.0.0.0:8443
password: 你的密码
padding-scheme: ./padding.txt   # 可选，padding 方案文件路径

# 外部 HTTP 鉴权（可选，留空则使用 password）
auth:
  type: http
  http:
    url: https://your-backend/auth
    insecure: false      # 是否跳过后端证书校验
    cacheTTL: 60s        # 缓存成功鉴权结果的时长，留空或 0 关闭缓存
    cacheSize: 4096      # 缓存条目上限，默认 4096

# 流量统计 HTTP API（可选，listen 留空则不启动）
trafficStats:
  listen: 127.0.0.1:9999
  secret: 你的密钥
```

### 外部 HTTP 鉴权后端

当 `auth.type: http` 且设置了 `url` 时，服务端会在握手阶段把凭据 POST 到外部后端，行为与 hysteria 2 一致：

- 请求：`POST`，`Content-Type: application/json`，请求体 `{"addr": "客户端IP:端口", "auth": "凭据(hex)", "tx": 0}`。
  - `tx` 在 hysteria 中为客户端声明的下行速率；AnyTLS 协议没有该字段，固定发送 `0`（即“未知”，与 hysteria 启用带宽探测时发送的值相同）。
- 响应：仅 HTTP `200` 视为成功，响应体 `{"ok": true, "id": "用户标识"}`。`ok=true` 时 `id` 原样透传（允许为空）；其余状态码或 `ok=false` 均拒绝。
- 客户端 10s 超时；`insecure` 控制是否跳过 TLS 校验；无重试。
- `cacheTTL > 0` 时，仅缓存**成功**结果（拒绝与后端错误始终穿透到后端），重连可跳过后端调用。

返回的 `id` 是流量统计的稳定键。未配置 HTTP 鉴权时，使用单一 `password`，其 `id` 为由密码哈希派生的稳定合成值（不泄露密码）。

### 流量统计 HTTP API

配置 `trafficStats.listen` 后启动，所有接口通过 `Authorization: <secret>` 头鉴权（`secret` 为空则不鉴权），与 hysteria 2 的接口一致：

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/traffic` | GET | 返回各 `id` 的累计流量：`{"<id>": {"tx": N, "rx": N}}` |
| `/traffic?clear=<真值>` | GET | 返回清零前快照，随后重置计数（`clear` 用 `strconv.ParseBool` 解析，`1`/`t`/`true` 等均可） |
| `/online` | GET | 返回各 `id` 当前在线会话数：`{"<id>": N}` |
| `/kick` | POST | 请求体为 `id` 数组 `["a","b"]`，断开这些 `id` 的所有会话，返回空 `200` |
| `/dump/streams` | GET | 返回当前所有活动流；默认 JSON `{"streams":[...]}`，`Accept: text/plain` 时返回 netstat 风格表格 |

`/dump/streams` 的每条记录字段与 hysteria 2 完全一致：`state`、`auth`、`connection`、`stream`、`req_addr`、`hooked_req_addr`、`tx`、`rx`、`initial_at`、`last_active_at`（时间为 RFC3339Nano）。其中 `hooked_req_addr` 恒为空——AnyTLS 没有请求改写（ACL）功能，这与 hysteria 在未命中改写规则时的输出相同。

内存仅由 `/traffic?clear=...` 回收（无后台清理协程，与 hysteria 一致）：离线条目删除，仍有活动会话的条目就地清零。
