# AnyTLS

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 一键安装

从 GitHub Release 下载预编译二进制（`anytls-server`、`anytls-client`），并安装 `anytls-manager`（Linux systemd 服务管理工具）：

```bash
curl -fsSL https://308.li/anytls-go | bash -s -- install
```

安装完成后，在 Linux 上可用交互式菜单配置并注册 systemd 服务：

```bash
anytls-manager
```

也可直接使用已有配置文件：

```bash
anytls-manager install-service -c /path/to/server.yaml
```

升级与卸载：

```bash
curl -fsSL https://308.li/anytls-go | bash -s -- upgrade
curl -fsSL https://308.li/anytls-go | bash -s -- uninstall
```

脚本源码见 [`scripts/install.sh`](scripts/install.sh)。默认安装目录为 `/usr/local/bin`，配置文件写入 `/etc/anytls/server.yaml`。

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

# TLS 证书（可选，留空则启动时自动生成临时自签证书；证书文件变更后无需重启）
tls:
  cert: /path/to/server.crt
  key: /path/to/server.key

# 外部 HTTP 鉴权（可选，留空则使用 password）
auth:
  type: http
  http:
    url: https://your-backend/auth
    insecure: false      # 是否跳过后端证书校验
    cacheTTL: 60s        # 缓存成功鉴权结果的时长，留空默认 10s，"0" 关闭缓存
    cacheSize: 4096      # 缓存条目上限，默认 4096
    negativeCacheTTL: 60s # 缓存拒绝结果的时长，留空默认 60s，"0" 关闭

# 流量统计 HTTP API（可选，listen 留空则不启动）
trafficStats:
  listen: 127.0.0.1:9999
  secret: 你的密钥

# 带宽限速（可选，留空或 0 表示不限速）
bandwidth:
  up: 100 mbps    # 服务器发送给客户端的最大速率（即客户端下载）
  down: 20 mbps   # 服务器接收客户端的最大速率（即客户端上传）
```

### 外部 HTTP 鉴权后端

当 `auth.type: http` 且设置了 `url` 时，服务端会在握手阶段把凭据 POST 到外部后端，行为与 hysteria 2 一致：

- 请求：`POST`，`Content-Type: application/json`，请求体 `{"addr": "客户端IP:端口", "auth": "凭据(hex)", "tx": 0, "variant": "geekdada/anytls-go"}`。
  - `auth` 为客户端握手凭据的 hex 编码，即 `hex(sha256(password))`（固定 64 个十六进制字符）。
  - `tx` 在 hysteria 中为客户端声明的下行速率；AnyTLS 协议没有该字段，固定发送 `0`（即“未知”，与 hysteria 启用带宽探测时发送的值相同）。
  - `variant` 固定为 `geekdada/anytls-go`，用于让被多种代理协议共用的后端区分出 anytls-go 的请求。
- 响应：仅 HTTP `200` 视为成功，响应体 `{"ok": true, "id": "用户标识"}`。`ok=true` 时 `id` 原样透传（允许为空）；其余状态码或 `ok=false` 均拒绝。
- 客户端 10s 超时；`insecure` 控制是否跳过 TLS 校验；无重试。
- `cacheTTL > 0` 时缓存**成功**结果，重连可跳过后端调用（留空默认 `10s`，设为 `"0"` 关闭）；同时按 `negativeCacheTTL` 缓存**拒绝**结果（`ok=false`），使不断重连的失效凭据不再反复打到后端（留空默认 `60s`，设为 `"0"` 可关闭）。**后端错误（非 200/网络故障）始终穿透**，不会被缓存，故后端故障不会误锁合法用户。成功与拒绝使用相互独立的缓存，避免大量不同的错误凭据挤占正常缓存条目。

返回的 `id` 是流量统计的稳定键。未配置 HTTP 鉴权时，使用单一 `password`，其 `id` 为由密码哈希派生的稳定合成值（不泄露密码）。

### 流量统计 HTTP API

配置 `trafficStats.listen` 后启动，所有接口通过 `Authorization: <secret>` 头鉴权（`secret` 为空则不鉴权），与 hysteria 2 的接口一致：

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/traffic` | GET | 返回各 `id` 的累计流量：`{"<id>": {"tx": N, "rx": N}}` |
| `/traffic?clear=<真值>` | GET | 返回清零前快照，随后重置计数（`clear` 用 `strconv.ParseBool` 解析，`1`/`t`/`true` 等均可） |
| `/online` | GET | 返回各 `id` 当前在线设备数（按 `auth`+源IP 去重）：`{"<id>": N}` |
| `/kick` | POST | 请求体为 `id` 数组 `["a","b"]`，断开这些 `id` 的所有会话，返回空 `200` |
| `/dump/streams` | GET | 返回当前所有活动流；默认 JSON `{"streams":[...]}`，`Accept: text/plain` 时返回 netstat 风格表格 |

`/dump/streams` 的每条记录字段与 hysteria 2 完全一致：`state`、`auth`、`connection`、`stream`、`req_addr`、`hooked_req_addr`、`tx`、`rx`、`initial_at`、`last_active_at`（时间为 RFC3339Nano）。其中 `hooked_req_addr` 恒为空——AnyTLS 没有请求改写（ACL）功能，这与 hysteria 在未命中改写规则时的输出相同。

`connection` 对应 hysteria 的「承载该流的 QUIC 连接」：在 AnyTLS 里它是**设备级逻辑连接**——同一设备（按 `auth`+源IP 推断）的多条池化 TLS 会话共享同一个 `connection`，其下的多个流以单调递增的 `stream` 编号，正如 hysteria 一个设备保持一条连接、连接内多路复用多个流。设备的多条会话全部断开后该 `connection` 释放，重连得到新 id（无后台清理协程）。用 IP 推断设备有两点局限：① 同一 NAT 公网 IP 后、用**同一** `auth` 的多台设备会被并为一个 `connection`（用不同 `auth` 则可区分）；② 设备 IP 变化（如移动网络漫游）会得到新的 `connection` id。

内存仅由 `/traffic?clear=...` 回收（无后台清理协程，与 hysteria 一致）：离线条目删除，仍有活动会话的条目就地清零。

### 带宽限速

配置 `bandwidth` 后，服务端对每个客户端的收发速率做上限控制，语义与 [hysteria 2](https://github.com/apernet/hysteria) 一致：

- `up` 是**服务器发送给客户端**的最大速率，对应**客户端下载**速度；`down` 是**服务器接收客户端**的最大速率，对应**客户端上传**速度。
- 留空或 `0` 表示该方向不限速；两个方向都不限速时限速器完全不介入。
- 支持的单位（不区分大小写，可含空格，按 1000 进制）：`bps`/`b`、`kbps`/`kb`/`k`、`mbps`/`mb`/`m`、`gbps`/`gb`/`g`、`tbps`/`tb`/`t`（数值为**每秒比特数**）；纯数字按 bps 处理。
- 限速以**设备**为单位（按 `auth`+源IP 推断，与 `/dump/streams` 的 `connection` 同一套识别逻辑）：同一设备的多条池化 TLS 会话共享同一对令牌桶，正如 hysteria 对单条 QUIC 连接限速。识别的局限与 `/dump/streams` 相同（同一 NAT 出口 IP 且用**同一** `auth` 的多台设备会被并为一个限速单位；设备 IP 变化会得到新的限速单位）。
- 通过令牌桶（`golang.org/x/time/rate`）配合 TCP 自然背压实现：限速仅作用于握手鉴权**之后**的会话数据流，鉴权与 fallback 不受影响。线路协议未改动，客户端无需改动。
