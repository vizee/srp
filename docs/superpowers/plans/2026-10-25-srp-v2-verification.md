# srp v2.0 验证记录

工作分支：`srp-v2`，工作区：`/tmp/srp-v2-worktree`。旧应用由新实现完全替换，尚未合并到主工作区。

## 已执行验证

| 检查 | 结果 |
| --- | --- |
| Go 工具链 | go1.27.0 linux/amd64，go.mod 最低 1.24 |
| `go test ./...` | 通过；包含真实 5/7 秒心跳、11 秒空闲隧道、多服务及半关闭验收 |
| `go test -race ./...` | 通过 |
| `go vet ./...` | 通过 |
| `go build -o /tmp/srp-v2 .` | 通过 |
| FuzzReadHello，5 秒/4 workers | 793950 次执行，无 crash |
| FuzzReadMessage，5 秒/4 workers | 793466 次执行，无 crash |
| `git diff --check` | 通过 |
| 真实 srp 二进制、独立 relay/expose 进程 | 两个服务转发通过 |
| 无注册时服务端口 | 不监听 |
| 端口冲突与恢复 | 注册成功、其他服务可用，端口释放后自动恢复 |
| SIGTERM | expose 退出，relay 服务端口关闭，relay 进程继续运行 |

## 实现中的决定

- Go 1.24+ 与标准库 HKDF，不提供旧 systemd-service 命令；代价是旧工具链不可构建，systemd unit 需手动安装。此项已包含在获批准的实施计划中。
- 将双方相同的 heartbeat 读写循环放在 protocol.RunControl 中；代价是增加一个共享内部接口，避免两端超时语义分叉。

## 回归证据

慢速首包测试先失败：服务端使用开始等待时的时间检查，错误拒绝读完首包时仍在合法偏差内的客户端。改为完整读取后取当前时间，测试由失败转为通过；完整协议测试及 race 同时通过。

## 独立审阅

独立审阅覆盖 `c48bb75..e7e54e3`，未发现 Critical，复现两项 Important；两项均由实现者编写失败回归、修复并重新通过全量普通/race/vet/build 及真实 CLI 验收。未进行第二轮独立审阅。

1. **建连槽位被长期会话占用**：原实现把 256 槽位持有到 Bridge 结束。`TestEstablishedConnectionsReleaseDialSlots` 先失败（第二个请求 busy），改为 data ready 后释放、结束时幂等兜底释放后通过。独立容量探针随后验证 **300 条同时建立的真实 TCP 连接全部成功收发**。
2. **监听 DNS 不响应取消**：原 net.Listen 不接收 context。`TestShutdownCancelsServiceDNS` 与 `TestCLICancellationInterruptsListenDNS` 先失败，改为 ListenConfig.Listen(ctx, ...) 后通过；取消也以状态码 0 正常退出。

还补充了以下定向验证：认证失败不会注册/消费有效 ID；ready 写入被阻塞的成员不参与调度；认领、超时释放与控制关闭竞争；控制关闭与目标拨号返回竞争；数据握手尚未完成时关闭控制会回收目标与隧道。

## 暂缓的低优先级项

首包原始字节 fuzz 没有为变异后的 JSON 重新生成合法 HMAC，不能据其执行次数宣称覆盖认证后的全部字段分支。HMAC 篡改、非法长度、时间边界等有确定性测试；可另增认证后字段 fuzz target，此次不扩展。

## 审阅中保留的既定范围与代价

- 不兼容 v1：两端必须同时升级，不提供兼容包装。
- 不跨控制重连保留/迁移业务：控制断开会中断所属业务连接，应用自行重连。
- 不发 cancel：relay 释放 ID 后，远端尚在进行的工作可能继续到自身预算结束，但不能认领旧 ID。
- 不进行 TCP 业务排空：进程退出关闭业务连接，可能中断尚未完成的应用交换。
- 不提供前向保密或同密钥租户隔离：共享密钥泄露可能影响历史录制流量，同密钥节点均受信任。
- 配对前不预读：避免把 CloseWrite 当完整关闭；尚未读取的 RST 可能延迟到配对后 I/O 或超时才观察到。

这些范围均来自用户决定或已批准计划，不因审阅自行增加兼容、保活、取消或排空机制。
