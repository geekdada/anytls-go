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

示例服务器未配置证书时会生成临时自签证书。示例客户端默认校验服务器证书，连接这类服务器时需加 `-insecure`（或在 URI 中写 `insecure=1`）。跳过校验后，中间人可以截获通信内容和握手凭据 `sha256(password)`，并用该凭据冒充您连接服务器。生产环境请为服务器配置受信任的证书（见 `tls` 配置）。

### 示例服务器

```
./anytls-server -l 0.0.0.0:8443 -p 密码
```

`0.0.0.0:8443` 为服务器监听的地址和端口。

### 示例客户端

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码 -insecure
```

`127.0.0.1:1080` 为本机 Socks5 代理监听地址，理论上支持 TCP 和 UDP(通过 udp over tcp 传输)。服务器使用受信任证书时去掉 `-insecure`；证书域名与服务器地址不同时用 `-sni` 指定。

v0.0.12 版本起，示例客户端可直接使用 URI 格式:

```
./anytls-client -l 127.0.0.1:1080 -s "anytls://password@host:port"
./anytls-client -l 127.0.0.1:1080 -s "anytls://password@host:port/?insecure=1"
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

本分支在上游 `anytls-go` 的基础上，为**服务端**新增了五个子系统，与 [hysteria 2](https://github.com/apernet/hysteria) 的对应功能保持一致（请求/响应格式、接口路径与副作用均对齐）。线路协议未作改动，与上游客户端互通。示例客户端改为默认校验服务器证书（见上文），旧的启动命令连接自签证书服务器时需加 `-insecure`。

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
    maxConcurrent: 64    # 同时进行的后端请求上限，默认 64

# ACL 规则（可选，file 与 inline 二选一，均留空则不启用）
acl:
  inline:
    - reject(suffix:example.com)
    - reject(all, udp/443)
    - direct(all)
  # file: /path/to/rules.acl      # 改为从文件加载规则
  # geoip: /path/to/geoip.dat     # 可选，留空首次用到时自动下载
  # geosite: /path/to/geosite.dat # 可选，留空首次用到时自动下载
  # geoUpdateInterval: 168h       # 可选，数据文件更新周期，默认 7 天

# 自定义 DNS 解析器（可选，留空或 system 表示使用系统解析器）
resolver:
  type: udp            # udp | tcp | tls | https
  udp:
    addr: 8.8.4.4:53   # 可省略端口，默认 53
    timeout: 4s        # 留空默认 2s
  # tcp:
  #   addr: 8.8.8.8:53      # 可省略端口，默认 53
  #   timeout: 4s
  # tls:                    # DNS over TLS
  #   addr: 1.1.1.1:853     # 可省略端口，默认 853
  #   timeout: 10s
  #   sni: cloudflare-dns.com
  #   insecure: false       # 是否跳过 DNS 服务器证书校验
  # https:                  # DNS over HTTPS
  #   addr: 1.1.1.1:443     # 也可直接写完整 URL，否则拼为 https://<addr>/dns-query
  #   timeout: 10s
  #   sni: cloudflare-dns.com
  #   insecure: false

# 流量统计 HTTP API（可选，listen 留空则不启动；启用时 secret 必填）
trafficStats:
  listen: 127.0.0.1:9999
  secret: 你的密钥

# 出站目标限制（可选）
outbound:
  allowPrivate: false   # 默认 false：禁止客户端访问回环、内网、链路本地等地址

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
- 同时进行的后端请求不超过 `maxConcurrent`（默认 64）。每个未命中缓存的握手都会请求后端，未鉴权的客户端可以用随机凭据持续发起握手，该上限避免请求在后端堆积。等待 2s 仍无空闲名额的握手按后端错误处理（拒绝且不缓存）。
- `cacheTTL > 0` 时缓存**成功**结果，重连可跳过后端调用（留空默认 `10s`，设为 `"0"` 关闭）；同时按 `negativeCacheTTL` 缓存**拒绝**结果（`ok=false`），使不断重连的失效凭据不再反复打到后端（留空默认 `60s`，设为 `"0"` 可关闭）。**后端错误（非 200/网络故障）始终穿透**，不会被缓存，故后端故障不会误锁合法用户。成功与拒绝使用相互独立的缓存，避免大量不同的错误凭据挤占正常缓存条目。

返回的 `id` 是流量统计的稳定键。未配置 HTTP 鉴权时，使用单一 `password`，其 `id` 为由密码哈希派生的稳定合成值（不泄露密码）。

### 流量统计 HTTP API

配置 `trafficStats.listen` 后启动，所有接口通过 `Authorization: <secret>` 头鉴权，与 hysteria 2 的接口一致。`secret` 必填，留空时启动失败，因为该 API 可以踢下线任意用户并列出所有用户的访问目标：

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/traffic` | GET | 返回各 `id` 的累计流量：`{"<id>": {"tx": N, "rx": N}}` |
| `/traffic?clear=<真值>` | GET | 返回清零前快照，随后重置计数（`clear` 用 `strconv.ParseBool` 解析，`1`/`t`/`true` 等均可） |
| `/online` | GET | 返回各 `id` 当前在线设备数（按 `auth`+源IP 去重）：`{"<id>": N}` |
| `/kick` | POST | 请求体为 `id` 数组 `["a","b"]`，断开这些 `id` 的所有会话，返回空 `200` |
| `/dump/streams` | GET | 返回当前所有活动流；默认 JSON `{"streams":[...]}`，`Accept: text/plain` 时返回 netstat 风格表格 |

`/dump/streams` 的每条记录字段与 hysteria 2 完全一致：`state`、`auth`、`connection`、`stream`、`req_addr`、`hooked_req_addr`、`tx`、`rx`、`initial_at`、`last_active_at`（时间为 RFC3339Nano）。其中 `hooked_req_addr` 目前恒为空（ACL 劫持改写未回填到统计），这与 hysteria 在未命中改写规则时的输出相同。

`connection` 对应 hysteria 的「承载该流的 QUIC 连接」：在 AnyTLS 里它是**设备级逻辑连接**——同一设备（按 `auth`+源IP 推断）的多条池化 TLS 会话共享同一个 `connection`，其下的多个流以单调递增的 `stream` 编号，正如 hysteria 一个设备保持一条连接、连接内多路复用多个流。设备的多条会话全部断开后该 `connection` 释放，重连得到新 id（无后台清理协程）。用 IP 推断设备有两点局限：① 同一 NAT 公网 IP 后、用**同一** `auth` 的多台设备会被并为一个 `connection`（用不同 `auth` 则可区分）；② 设备 IP 变化（如移动网络漫游）会得到新的 `connection` id。

内存仅由 `/traffic?clear=...` 回收（无后台清理协程，与 hysteria 一致）：离线条目删除，仍有活动会话的条目就地清零。

### ACL 规则

配置 `acl` 后，服务端按 [hysteria 2 的 ACL](https://v2.hysteria.network/zh/docs/advanced/ACL/) 语法与匹配语义过滤客户端请求，但**不包含 outbounds 控制**：规则目标只有内置的 `direct`（直连）、`reject`（拒绝）、`default`（等同 `direct`），使用其他出站名会在启动时报错。

- 规则自上而下匹配，首个命中生效；全部未命中默认 `direct`。支持 `#` 注释。
- 地址类型与 hysteria 一致：单个 IP、CIDR、域名、`*.example.com` 通配、`suffix:` 域名后缀、`geoip:xx`、`geosite:xx`（支持 `@attr` 标签）、`all`。
- `proto/port` 与劫持地址语义一致，如 `reject(all, udp/443)` 屏蔽 QUIC、`direct(8.8.8.8, udp/53, 1.1.1.1)` 劫持目标地址（仅 IP，不可为域名）。
- 与 hysteria 相同，域名请求会先解析再匹配，IP 类规则对域名请求同样生效；TCP 直接拨解析出的 IP。解析所用的 DNS 服务器可通过 [`resolver`](#自定义-dns-解析器) 指定，留空则用系统解析器。
- UDP（udp over tcp）按**每个报文**的目标地址检查：命中 `reject` 的报文静默丢弃、流保持存活；命中劫持规则的报文改写目标地址。决策按目标地址在流生命周期内缓存。
- `geoip:`/`geosite:` 使用 v2ray 数据文件；未配置 `acl.geoip`/`acl.geosite` 路径时自动下载（Loyalsoldier v2ray-rules-dat），并按 `acl.geoUpdateInterval` 周期更新（默认 7 天）。
- `file` 与 `inline` 互斥；规则编译失败会导致启动失败。

### 出站目标限制

默认禁止客户端连接以下地址：回环（`127.0.0.0/8`、`::1`）、私有网段（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`）、链路本地（`169.254.0.0/16`、`fe80::/10`，含云服务器元数据地址 `169.254.169.254`）、共享地址（`100.64.0.0/10`）、`0.0.0.0/8`、广播与组播地址。这样代理用户无法访问服务器本机的服务（例如流量统计 API）、服务器所在内网或云元数据接口。

- 域名目标会先解析，按解析出的 IP 检查并直接拨该 IP，域名指向内网地址同样会被拒绝。未配置 `resolver` 时使用系统解析器。
- 检查在 ACL 之后进行：ACL 的 `reject` 优先；ACL 劫持规则的目标地址由运维指定，不受此限制。
- TCP 请求被拒时客户端收到 `blocked by server policy`；UDP（udp over tcp）报文静默丢弃、流保持存活。
- 需要通过代理访问内网时设置 `outbound.allowPrivate: true`，启动日志会给出警告。

### 连接保护

- TLS 握手与读取鉴权数据须在 10s 内完成，否则断开连接，避免静默连接长期占用资源。
- 新建流后须在 10s 内发来目标地址（UoT 还包括 UoT 请求头），否则关闭该流。
- 每条 TLS 会话最多同时打开 1024 条流。超出时 v2 客户端收到带错误信息的 `SYNACK`，v1 客户端收到 `FIN`。
- 发给客户端的出站错误只包含类别（`blocked by server policy`、`resolve failed`、`dial failed`），完整错误只记录在服务端日志中，避免泄露解析器地址等内部信息。

### 自定义 DNS 解析器

配置 `resolver` 后，服务端用指定的 DNS 服务器解析出站目标域名，语义与 [hysteria 2 的 resolver](https://v2.hysteria.network/zh/docs/advanced/Full-Server-Config/#resolver) 一致：

- `type` 取值：`udp`、`tcp`、`tls`（DNS over TLS，别名 `tcp-tls`）、`https`（DNS over HTTPS，别名 `http`）；不区分大小写。留空或 `system` 表示系统解析器。其他取值启动时报错。
- 只读取 `type` 对应的子块。`addr` 必填，缺省端口为 `53`（udp/tcp）或 `853`（tls）；`https` 的 `addr` 非 `https://` 开头时拼为 `https://<addr>/dns-query`。
- `timeout` 留空默认 `2s`，且该超时是**单次 DNS 交换**的超时；含重试与 CNAME 跟随时总耗时可能超过它。
- `sni` 覆盖 TLS 的 server name（`addr` 为 IP 时通常必需），`insecure: true` 跳过 DNS 服务器证书校验。
- A 与 AAAA **并行**查询，各重试 2 次，只取第一条 A 和第一条 AAAA；DoH 不重试（与 hysteria 一致）。同一报文内的 CNAME 链会被折叠，跟随深度上限 16 并检测环路。
- 配置了自定义解析器后，**无论是否启用 ACL**，服务端都用它解析域名并直连解析结果。解析不出任何地址时 TCP 请求失败（错误形如 `resolve error: ...`），**不回退系统解析器**，避免 DNS 泄漏；UDP（udp over tcp）报文静默丢弃、流保持存活（与 ACL 拒绝的报文同样处理，因为一条流复用多个目标）。
- 解析失败仍会先过 ACL：域名类 `reject` 规则照常生效，劫持规则也能救回解析不出的域名（与 hysteria 的 `Resolver(ACL(outbound))` 顺序一致）。
- 目标本身是 IP 时不发起任何查询。
- 未配置（或 `system`）时：启用 ACL 或[出站目标限制](#出站目标限制)（默认启用）时用系统解析器预解析；只有设置 `outbound.allowPrivate: true` 且未启用 ACL 时才不预解析，由拨号器自行解析。
- 无 DNS 缓存（与 hysteria 一致）；UDP 路径按目标地址在流生命周期内缓存决策。双栈时优先 IPv4，不做 Happy Eyeballs 竞速。
- `tcp` 与 `tls` 解析器复用到 DNS 服务器的连接（每个解析器最多保留 8 条空闲连接），避免每次查询都重新进行 TCP/TLS 握手；服务器关闭了空闲连接时自动换新连接重发。`udp` 每次查询使用新套接字，`https` 由 HTTP 客户端复用连接。
- 该配置仅作用于服务端出站解析；客户端与 `acl.geoip`/`acl.geosite` 数据文件下载仍走系统解析器（与 hysteria 相同）。

### 带宽限速

配置 `bandwidth` 后，服务端对每个客户端的收发速率做上限控制，语义与 [hysteria 2](https://github.com/apernet/hysteria) 一致：

- `up` 是**服务器发送给客户端**的最大速率，对应**客户端下载**速度；`down` 是**服务器接收客户端**的最大速率，对应**客户端上传**速度。
- 留空或 `0` 表示该方向不限速；两个方向都不限速时限速器完全不介入。
- 支持的单位（不区分大小写，可含空格，按 1000 进制）：`bps`/`b`、`kbps`/`kb`/`k`、`mbps`/`mb`/`m`、`gbps`/`gb`/`g`、`tbps`/`tb`/`t`（数值为**每秒比特数**）；纯数字按 bps 处理。
- 限速以**设备**为单位（按 `auth`+源IP 推断，与 `/dump/streams` 的 `connection` 同一套识别逻辑）：同一设备的多条池化 TLS 会话共享同一对令牌桶，正如 hysteria 对单条 QUIC 连接限速。识别的局限与 `/dump/streams` 相同（同一 NAT 出口 IP 且用**同一** `auth` 的多台设备会被并为一个限速单位；设备 IP 变化会得到新的限速单位）。
- 通过令牌桶（`golang.org/x/time/rate`）配合 TCP 自然背压实现：限速仅作用于握手鉴权**之后**的会话数据流，鉴权与 fallback 不受影响。线路协议未改动，客户端无需改动。
