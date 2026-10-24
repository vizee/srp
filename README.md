# srp v2.0

零配置文件的 TCP 反向代理。内网侧运行 `expose`，公网侧运行 `relay`；一个 expose 可提供多个命名服务，多个 expose 可共同提供同一服务，relay 按连接次数独立轮询。

v2 完全重新开发，不兼容旧命令和旧线协议。只提供 `expose`、`relay`、`version`，不读取运行配置文件。

## 构建

需要 Go 1.24 或更新版本，仅使用标准库。

```sh
go build -o srp .
./srp version
```

## 共享密钥

两端部署同一份原始二进制密钥文件，支持 16、24、32 字节，推荐生成 32 字节：

```sh
install -d -m 700 "$HOME/.config/srp"
umask 077
openssl rand -out "$HOME/.config/srp/default.key" 32
```

把生成的文件安全复制到另一端；不要在两端分别生成不同的密钥。不指定 `-k` 时读取 `$HOME/.config/srp/default.key`。程序不会自动生成密钥，不对文件进行 trim 或 Base64 解码；`-k` 直接接受文件路径，不使用旧版的 `@` 前缀。

## 运行

公网 relay：

```sh
./srp relay -k /path/to/shared.key -l :7770 \
  -s 'ssh=:8022,myweb=100.100.100.100:18080,egress.baidu=127.0.0.1:443'
```

能够访问目标服务的 expose：

```sh
./srp expose -k /path/to/shared.key -r 100.100.100.100:7770 \
  -t 'ssh=127.0.0.1:22,myweb=192.168.1.11:8080,egress.baidu=www.baidu.com:443'
```

服务名两端对应；真实目标地址只由 expose 保存、解析及连接，不会传给 relay。

```sh
ssh -p 8022 user@100.100.100.100
curl http://100.100.100.100:18080/
```

`100.100.100.100` 必须是 relay 主机可使用的地址。relay 上绑定 `127.0.0.1:443` 的服务仅对该主机本地开放。需要允许 expose 访问隧道 TCP 7770，以及客户端访问相应服务端口。

## 参数

```text
srp [-v] expose [-k key-file] [-r host:7770] -t service=host:port,...
srp [-v] relay  [-k key-file] [-l :7770]    -s service=host:port,...
srp version
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-k` | `$HOME/.config/srp/default.key` | 原始共享密钥文件路径 |
| expose `-r` | `127.0.0.1:7770` | relay 隧道入口 |
| expose `-t` | 必填 | 多个服务名与目标地址 |
| relay `-l` | `:7770` | 控制与数据连接共用的隧道入口 |
| relay `-s` | 必填 | 多个服务名与监听地址 |
| `-v` | 关闭 | 额外记录握手及数据建连失败，放在子命令前 |

服务名区分大小写，仅允许 1–128 个 ASCII 字母、数字、点、下划线、短横线；每次最多配置 256 个服务。同一次命令中服务名不能重复。地址使用 `host:port`，IPv6 例如 `ssh=[::1]:22`；端口必须为 1–65535。监听 host 可以为空，目标 host 必须明确指定。密钥文件路径可包含空格，使用 shell 引号即可。

## 注册、监听与故障处理

- relay 启动只监听隧道入口。服务首次有 expose 注册时才开启监听；最后一个 expose 注销后停止监听。
- 每个服务由独立管理协程管理 listener。bind 失败记录警告并每秒重试，注册、心跳和其他服务仍正常；端口释放后自动恢复。
- expose 声明但 relay 未配置的服务列为 ignored 并记录日志；若没有任何匹配服务则拒绝注册。
- 多个 expose 提供相同服务时按新客户端连接轮询，不按流量或并发数加权。
- 每条客户端连接对应一条独立的数据隧道；不复用 TCP 字节流，不迁移已建立会话。
- 控制连接双方每 5 秒 heartbeat，7 秒未收到 heartbeat 即断开。控制关闭会注销服务并关闭其所有待配对及已建立的数据会话，业务客户端需自行重连。
- expose 自动重连控制连接，退避约 1、2、4、8、最高 10 秒，加少量抖动；稳定连接 30 秒后复位。
- 数据连接在完整握手首包发送成功前发生建连/发送失败可在预算内重试；完整首包发送成功后，该数据 ID 不再重试。未知、超时、已使用的 ID 直接拒绝。
- 目标拨号最多 5 秒；一次 open 总预算 10 秒；relay 等待配对最多 15 秒。新隧道认证握手最多 5 秒。
- 已建立业务连接没有额外空闲超时，支持 TCP 半关闭。客户端发送结束后可以继续接收响应，配对前 CloseWrite 也不会提前释放 ID。
- SIGINT/SIGTERM 关闭 listener、控制连接及所有业务连接，清理协程后退出，不等待业务排空。

仅转发 TCP，不支持 UDP、HTTP 路由或转发原始客户端 IP；目标看到的 TCP 对端是 expose。

## 协议与认证加密

首包格式：

```text
IV[16] | AES-CTR(nonce[24] | JSON长度[4] | JSON | HMAC-SHA256[32])
```

HMAC 覆盖 IV、nonce、长度和 JSON，使用与 CTR 独立派生的密钥，不叠加 CRC。握手只包含版本、控制/数据类型、服务名或一次性数据 ID、客户端 Unix 毫秒时间。

时间领先或落后达到 10 秒即拒绝，部署两端需保持系统时间同步。relay 全局原子查重 nonce，内存保留 20 秒；控制/数据连接共用表，连接关闭不提前删除。随机服务端挑战与加密确认验证当前会话，避免只重放首包就注册或消费数据 ID，也保护 relay 重启后 nonce 缓存为空的情况。

双方使用标准库 HKDF-SHA256，为每条连接的两个方向独立派生 AES-256-GCM 密钥；后续控制消息和业务流均经过认证加密。GCM 记录使用递增序号、认证长度及认证 EOF，单记录最多 32 KiB，每方向最多 2^32 个记录，达到上限关闭连接。

加密覆盖 expose ↔ relay。客户端 ↔ relay、expose ↔ 目标这两段沿用业务原有协议。共享同一密钥的节点属于同一信任域，服务名不是租户隔离凭证；该方案不提供前向保密。

## 资源上限

| 资源 | 上限 |
| --- | --- |
| 并发隧道认证握手 | relay 256 |
| 全局 nonce 表 | 65536 条，保留 20 秒 |
| relay 待配对请求 | 4096 |
| 每控制连接待配对请求 | 256 |
| 每 expose 并发目标拨号/数据握手 | 256，ready 后释放槽位 |
| 控制消息发送队列 | 256 |
| 握手与控制 JSON | 65536 字节 |

达到上限时拒绝新请求，不提前驱逐仍有效的 nonce。活动数据连接受操作系统资源限制。所有容量均为内置值，无运行配置文件。

## systemd 示例

把二进制放在最终路径，密钥使用绝对路径，然后手动安装 unit，例如 expose：

```ini
[Unit]
Description=srp expose
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/srp expose -k /etc/srp/shared.key -r 100.100.100.100:7770 -t ssh=127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

程序不生成或安装 unit。注意运行用户读取默认密钥的 HOME 可能与交互用户不同，服务中建议显式指定密钥路径。

## 验证

```sh
go test ./...
go test -race ./...
go vet ./...
go test ./internal/protocol -run '^$' -fuzz FuzzReadHello -fuzztime 5s
go test ./internal/protocol -run '^$' -fuzz FuzzReadMessage -fuzztime 5s
```

测试需要允许本机 loopback TCP socket。包含真实心跳与超时验收，完整测试需要十余秒。

## 许可证

[MIT](LICENSE)
