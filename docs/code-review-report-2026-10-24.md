# 代码审查报告

- **日期**：2026-10-24
- **范围**：`srp` 全部实现代码（`main.go`、`link.go`、`agent.go`、`relay.go`、`protocol.go`、`crypto.go`、`encrypted_conn.go`、`systemd.go`）
- **结论**：发现 6 个问题（2 个高、3 个中、1 个低），全部经人工逐一复核确认属实。所有问题均为既有逻辑问题，与近期文件整理重构无关（重构已验证为逐字搬移、无行为漂移）。
- **复查（2026-10-24）**：6 个问题已全部修复（提交 `87c4011`、`ba4c84c`、`4b8135c`、`58b0303`、`74368d5`），修复正确性已逐项验证，`go build`/`go vet`/`go test` 通过。残余两个低风险瑕疵见文末。

---

## 1. 🔴 预读失败后未 `return`，已关闭的连接仍被投递给 relay

- **位置**：`link.go:123-125`
- **状态**：✅ 已确认（逐行复核）

```go
_, err := io.ReadFull(conn, preRead)
conn.SetReadDeadline(time.Time{})
if err != nil {
    conn.Close()   // 关闭了连接，但没有 return
}
select {
case l.accept <- &UserConn{conn: conn, preRead: preRead}:  // 死连接仍入队
```

**触发条件**：link 以 `-preRead N` 启动时，客户端发送不足 N 字节（如端口扫描器）或 3 秒内不发送数据。

**影响链**：
1. `io.ReadFull` 出错 → `conn.Close()`，但落入下方 `select`，已关闭的 conn 进入 `l.accept`；
2. `link()`（`link.go:67`）取出该死连接，向 agent 发送 `dial` 请求；
3. agent 真实地拨号后端目标并回 ack 成功；
4. `handleAgent`（`link.go:111`）调用 `relay(encrypted, uc.conn, ...)`，在已关闭的 conn 上立即失败。

**危害**：每个异常客户端消耗一次完整的 agent 配对周期和一次无意义的后端拨号；持续扫描会反复消耗 agent 连接并拖慢正常用户的接入。

**修复建议**：`conn.Close()` 后追加 `return`（一行改动，优先修复）。

---

## 2. 🔴 agent 后端拨号无超时，卡死整个重连循环

- **位置**：`agent.go:83`（另 `agent.go:22` 对 link 的拨号同样无超时）
- **状态**：✅ 已确认（逐行复核）

```go
bc, err = net.Dial("tcp", target)   // 无 deadline
```

```go
func (a *AgentMode) pairing() {
    rc, bc, ok := a.connectAndPair()   // 同步调用，拨号卡住则整个函数卡住
    ...
    go a.pairing()                     // 必须等 connectAndPair 返回才会 spawn 下一轮
```

**触发条件**：目标 IP 被 DROP（不回 RST），`net.Dial` 阻塞数分钟无 deadline。

**影响链**：唯一的 pairing goroutine 卡在拨号上 → agent 无法建立任何新的备用连接 → 新用户连接在 link 侧 `handleConn` 的 `select` 中等待 30 秒后被静默关闭（`link.go:129`）。

**修复建议**：改用 `net.DialTimeout("tcp", target, 10*time.Second)`（对 `a.remote` 的拨号同样处理）。

---

## 3. 🟠 默认配置完全不可用，且文档未说明

- **位置**：`agent.go:79` + `link.go:150`、`agent.go:144`
- **状态**：✅ 已确认（逐行复核）

- link 侧 `-t` 默认 `""`（`link.go:150`），dial 请求中原样发送 `target: ""`（`link.go:71`）；
- agent 侧 `-t` 默认 `""`（`agent.go:144`），`a.target != ""` 判断被跳过（`agent.go:79-81`）；
- 最终执行 `net.Dial("tcp", "")` → `dial tcp: missing address`，每次配对必失败。

**影响**：`srp link` 与 `srp agent` 双双以默认参数启动时，agent 永远处于重试循环，无法服务任何连接。两侧的 flag help（"target"）和 README 均未说明必须有一侧显式指定 `-t`。

**修复建议**（任选其一或组合）：
- 启动时校验：若 `link.target` 与 `agent.target` 均为空则 `fatalf` 并给出明确提示；
- 至少在 flag help 中标注必填性，如 `"target (required on either link or agent)"`。

---

## 4. 🟠 `-idleTimeout` 名不符实，仅覆盖首个请求的等待

- **位置**：`agent.go:47-54`
- **状态**：✅ 已确认（逐行复核）

```go
if a.idleTimeout > 0 {
    rc.SetReadDeadline(time.Now().Add(a.idleTimeout))   // 只覆盖等待 dial 请求
}
err = recvObject(rc, tmpKey[:], &data)
if a.idleTimeout > 0 {
    rc.SetReadDeadline(time.Time{})                     // 立即清零
}
```

之后 `relay(rc, bc, nil)`（`agent.go:128`）运行期间不受任何空闲超时约束。

**影响**：`srp agent -idleTimeout 1m` 的使用者预期"空闲连接会被回收"，实际只限制"agent 等待 link 发来第一个 dial 请求"的时长。已建立但长期静默的 relay 永不回收；link 接受 hello 后 stall 的连接同样无限占用资源（默认 3h 仅放宽了此问题，未消除）。

**修复建议**：要么实现真正的 relay 空闲超时（在 relay 中基于 read deadline + 活动重置），要么将 flag 更名为 `helloTimeout` 之类以反映实际语义。

---

## 5. 🟠 systemd unit 生成未做转义，路径/参数含空格即损坏

- **位置**：`systemd.go:48-51`
- **状态**：✅ 已确认（逐行复核）

```go
args := strings.Join(flag.Args(), " ")
if args != "" {
    cmdline += " " + args
}
// ExecStart=%s  ← 原样嵌入，无任何引号/转义
```

**触发条件**：
- 二进制安装于含空格路径，如 `/opt/my apps/srp` → systemd 将 `/opt/my` 解析为程序，服务以 `status=203/EXEC` 启动失败；
- 参数含空格，如 `srp systemd-service agent -r 'my host:7771'` → 同样被错误切分。

**修复建议**：对可执行路径与每个参数做 systemd 引号转义（`"` 包裹 + `"`/`\`、`$` 等 systemd 特殊字符转义），再拼入 `ExecStart`。

---

## 6. ⚪ 拼写错误：`foramt` → `format`

- **位置**：`main.go:11`
- **状态**：✅ 已确认（逐行复核）

```go
func dprintf(foramt string, args ...any) {
```

纯清理成本：旧代码带入新文件，影响补全与 grep。一行改名即可。

---

## 复核说明与总体评价

- **复核方式**：6 个问题均未采信单一来源，逐条对照 `link.go`、`agent.go`、`systemd.go`、`main.go` 全文重走代码路径确认，含完整的触发链验证。
- **重构本身**：审查代理已对整理重构提交做了逐声明 diff（39 个生产声明 + 37 个测试声明），确认与重构前单文件版本逐字一致，`go build`/`go vet`/`go test` 通过，测试覆盖完整保留。
- **握手与 relay 主路径**：half-close 链路（`relay`/`pipe`/`encryptedConn`）确认正确——EOF 只向 后端 方向回传、不会回灌到 agent 链路；ack-reader 到 `newEncryptedConn` 的交接无并发读。

### 优先级建议

| 优先级 | 问题 | 工作量 |
|---|---|---|
| P0 | #1 预读失败缺 `return` | 1 行 |
| P1 | #2 拨号无超时 | 2 行 |
| P1 | #3 默认配置不可用 | 校验 + 提示 |
| P2 | #4 idleTimeout 语义 | 需设计（实现真正的 relay 空闲超时或改名） |
| P2 | #5 systemd 转义 | 需实现转义函数 |
| P3 | #6 拼写 | 1 行 |

---

## 复查结果（2026-10-24）

6 个问题已全部修复并逐项验证通过：

| # | 问题 | 修复提交 | 验证 |
|---|---|---|---|
| 1 | 预读失败缺 `return` | `27c52aa` | ✅ `link.go:123-126` 已 `conn.Close(); return`，死连接不再入队 |
| 2 | 拨号无超时 | `87c4011` | ✅ 对 link 拨号 `DialTimeout(10s)`（`agent.go:23`），对后端拨号 `DialTimeout(5s)`（`agent.go:95`） |
| 3 | 默认配置不可用 | `ba4c84c` | ✅ target 为空时回 `success:false` + 错误信息（`agent.go:83-93`），link 侧既有 ack 逻辑正确判定失败；两侧 flag help 均标注 required |
| 4 | idleTimeout 名不符实 | `4b8135c` | ✅ 采用文档澄清方案，help 明确为"等待 dial 请求的超时，不影响已建立的 relay" |
| 5 | systemd 未转义 | `58b0303` | ✅ `systemdCommandLine()`：`strconv.Quote` 逐词包裹 + `%`→`%%` + 参数 `$`→`$$` |
| 6 | `foramt` 拼写 | `74368d5` | ✅ 已改为 `format` |

`go build` / `go vet` / `go test` 全部通过。

### 复查发现的残余瑕疵（低风险，不阻塞）

1. **`agent.go:85`**：target 缺失时每次配对重试（1s 间隔）都向 stderr 打印错误，无人值守场景会持续刷屏；建议仅在首次打印或 `fatalf` 退出。
2. **`systemd.go:14`**：可执行路径未做 `$`→`$$` 转义。多数 systemd 版本对整个命令行（含 argv[0]）做 env 替换，但路径来自 `os.Executable()`，实际几乎不可能含 `$`，风险可忽略。
