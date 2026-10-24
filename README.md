# srp

Simple Reverse Proxy，一个使用 Go 标准库实现的 TCP 反向代理。内网侧主动连接公网节点，将本地服务通过加密隧道暴露给外部客户端。

## 工作原理

程序包含两个角色：

- **link**：运行在外部可访问的主机上，分别监听用户端口和 agent 接入端口。
- **agent**：运行在能够访问目标服务的主机上，主动连接 link，并根据请求连接目标服务。

```text
外部客户端 <-- TCP --> Host A / link:7770
                              |
                       加密 TCP 隧道 :7771
                              |
                      Host B / agent <-- TCP --> 目标服务
```

agent 主动连接 Host A 的 `7771` 端口，内网侧无需开放入站端口。每条用户连接独占一条隧道，配对成功后 agent 会补充新的待命连接。支持并发连接和 TCP 半关闭；客户端结束发送后，仍可继续接收目标服务的响应。

srp 转发 TCP 字节流，可用于 HTTP、SSH 等基于 TCP 的服务；不支持 UDP。

## 构建

需要 Go 1.20 或更高版本。在项目目录执行：

```sh
go build -o srp .
```

## 快速开始

假设 Host A 是公网主机，Host B 上有一个监听 `127.0.0.1:80` 的 HTTP 服务。

### 1. 生成共享密钥

```sh
umask 077
openssl rand -out srp.key 32
```

将同一个 `srp.key` 文件放到 Host A 和 Host B。后续命令中的 `@./srp.key` 表示从文件读取原始密钥。

### 2. 在 Host A 启动 link

```sh
./srp link -k @./srp.key
```

默认使用 `:7770` 接收客户端连接，使用 `:7771` 接收 agent 连接。允许客户端访问 Host A 的 TCP `7770` 端口，并允许 Host B 访问 TCP `7771` 端口。

### 3. 在 Host B 启动 agent

将 `HOST_A` 替换为 Host A 的 IP 地址或域名：

```sh
./srp agent -k @./srp.key -r HOST_A:7771 -t 127.0.0.1:80
```

### 4. 访问目标服务

在能够访问 Host A 的客户端执行：

```sh
curl http://HOST_A:7770/
```

请求经 Host A 转发到 Host B 的 `127.0.0.1:80`。

## 命令与参数

```text
srp [-v] <command> [options]
```

`-v` 开启调试日志，必须放在子命令前，例如：

```sh
./srp -v agent -k @./srp.key -r HOST_A:7771 -t 127.0.0.1:80
```

使用 `./srp link -h`、`./srp agent -h` 或 `./srp systemd-service -h` 查看对应帮助。

### link

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-l` | `:7770` | 客户端连接的监听地址 |
| `-a` | `:7771` | agent 连接的监听地址 |
| `-k` | 空 | 共享密钥，两端需配置相同的值 |
| `-t` | 空 | 下发给 agent 的默认目标地址 |
| `-preRead` | `0` | 配对前从客户端读取的字节数；`0` 表示不预读 |

例如，使用自定义端口转发 SSH：

```sh
# Host A
./srp link -k @./srp.key -l :2222 -a :7771

# Host B
./srp agent -k @./srp.key -r HOST_A:7771 -t 127.0.0.1:22

# 外部客户端
ssh -p 2222 user@HOST_A
```

### agent

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-r` | `localhost:7771` | link 的 agent 接入地址，对应 link 的 `-a` |
| `-t` | 空 | 目标服务地址；设置后覆盖 link 下发的 `-t` |
| `-k` | 空 | 共享密钥，两端需配置相同的值 |
| `-idleTimeout` | `3h` | 待命连接等待拨号指令的超时；设为 `0` 可禁用 |

目标地址始终由 **agent 所在主机** 解析和连接。例如，无论 `127.0.0.1:80` 配置在 link 还是 agent 上，都指向 agent 所在主机。两端至少有一端需要设置 `-t`。

agent 连接或配对失败后间隔 1 秒重试。`-idleTimeout` 仅限制待命阶段，不限制已经建立的业务连接。

### 预读

`link -preRead N` 会等待客户端先发送完整的 `N` 字节，再将连接交给 agent。预读数据会在配对后先行加密转发，不会丢弃。

预读超时为 3 秒，未读满会关闭客户端连接。对于需要服务端先发送数据的协议，应保留默认的 `-preRead 0`。客户端连接等待可用 agent 的时间最多为 30 秒。

## 密钥与加密

### 共享密钥

link 和 agent 均需通过 `-k` 配置共享密钥，支持两种形式：

| 形式 | 示例 | 读取方式 |
| --- | --- | --- |
| 密钥文件 | `-k @./srp.key` | 直接读取文件中的原始字节 |
| Base64 字符串 | `-k BASE64_KEY` | 将参数按标准 Base64 解码 |

解码或读取后的密钥长度必须为 **16、24 或 32 字节**。`-k` 不是口令，程序不会从任意文本派生密钥；密钥文件内容也不会再次进行 Base64 解码。快速开始中生成的是 32 字节二进制密钥。

### 业务会话密钥

业务数据不直接使用 `-k` 加密：

1. agent 为每条隧道生成 16 字节随机临时密钥，通过共享密钥加密的握手发送给 link。
2. link 生成 16 字节随机会话标识，通过临时密钥加密的控制通道发送给 agent，并要求在确认消息中回传。
3. 双方使用 HMAC-SHA256，根据临时密钥、会话标识及方向标签，派生两个 32 字节 AES-GCM 密钥，分别保护 link → agent 和 agent → link 的业务数据。

握手和控制消息采用 AES-CBC 封装。业务数据使用 AES-GCM，每帧最多携带 32 KiB 明文，预读数据也经过相同加密。独立的方向密钥、递增的 nonce 和认证结束帧用于检测数据篡改、帧重放、顺序异常及流截断，同时保留半关闭语义。

加密覆盖 **link ↔ agent** 的隧道。客户端 ↔ link、agent ↔ 目标服务这两段沿用业务原有协议；业务自身使用的 HTTPS、SSH 等加密会继续保留。

### 版本兼容

当前业务传输协议为 `aes-gcm-v1`。**link 和 agent 必须同步升级**；旧版本或不支持该协议的对端会被拒绝，不会回退到明文转发。

## systemd

`systemd-service` 输出 service unit 文本，不会自动安装或启动服务。生成的 `ExecStart` 使用当前程序的绝对路径，因此应先把二进制放到最终安装位置。

以下为在 Host B 安装 agent 服务的示例，使用与 Host A 相同的密钥文件：

```sh
sudo install -m 755 ./srp /usr/local/bin/srp
sudo install -d -m 700 /etc/srp
sudo install -m 600 ./srp.key /etc/srp/srp.key

/usr/local/bin/srp systemd-service agent \
  -k @/etc/srp/srp.key \
  -r HOST_A:7771 \
  -t 127.0.0.1:80 > srp-agent.service

sudo install -m 644 srp-agent.service /etc/systemd/system/srp-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now srp-agent.service
```

生成 link 的 unit 时，将 `agent` 及其参数替换为 `link` 及对应参数。

| 生成参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-after` | `network-online.target` | unit 的 `After` |
| `-restart` | `always` | 服务重启策略 |
| `-restart-sec` | `3` | 重启间隔，单位为秒 |

这些生成参数必须放在服务子命令之前，例如：

```sh
./srp systemd-service -restart-sec 5 agent -k @/etc/srp/srp.key -r HOST_A:7771 -t 127.0.0.1:80
```

## 测试

```sh
go test ./...
go test -race ./...
go vet ./...
```

部分测试会监听本机 TCP 端口，运行环境需要允许创建本地 socket。

## 许可证

[MIT](LICENSE)
