# SSHShield

SSH 暴力破解防护：实时读取 sshd 日志，同一 IP 在时间窗口内失败达到阈值即通过 nftables / iptables 封禁，
重复作恶封禁时长递增。按 IP 记录失败次数、封禁次数、尝试过的用户名，同时维护全局总计与每日统计，
并提供 TUI 面板查看和操作。

## 一键安装

```bash
# 发布包（内含 amd64/arm64 二进制）解压后：
sudo ./install.sh

# 或直接从 GitHub Release 安装
curl -fsSL https://raw.githubusercontent.com/iccyuan/sshshield/main/install.sh | sudo bash

# 已有二进制时也可以：
sudo ./sshshield-linux-amd64 install
```

安装程序会：复制到 `/usr/local/bin/sshshield`；没有 nft/iptables 时自动装 nftables；
生成 `/etc/sshshield/config.json`，**并把当前登录的 SSH 客户端 IP 加进白名单，避免把自己锁在外面**；
最后注册并启动 systemd 服务 `sshshield`。

卸载：`sudo sshshield uninstall`（加 `--purge` 连配置和统计数据一起删）。

## 使用

| 命令 | 说明 |
| --- | --- |
| `sudo sshshield` | TUI 面板 |
| `sudo sshshield status` | 文字版统计 + 封禁列表 + Top 10 |
| `sudo sshshield ban 1.2.3.4 24h` | 手动封禁（不写时长则按递增规则） |
| `sudo sshshield unban 1.2.3.4` | 解封 |
| `sudo sshshield allow 1.2.3.0/24` | 加入白名单（写回配置、立即生效，覆盖到的已封禁 IP 会解封） |
| `sudo sshshield disallow 1.2.3.0/24` | 移出白名单 |
| `journalctl -u sshshield -f` | 守护进程日志（每次封禁/解封都有记录） |

TUI 键位：`↑↓/jk` 移动，`←→/Tab/1-5` 切换页，`u` 解封，`b` 封禁，`w` 把选中 IP 加白，`/` 过滤，`s` 排序（攻击来源页），
`r` 刷新，`q` 退出；白名单页里 `a` 添加、`d` 删除。
五个页签：封禁中 / 攻击来源 / 最近事件（最近 500 条）/ 用户名排行 / 白名单；顶部卡片显示总失败次数、今日失败、当前封禁、
累计封禁、今日封禁、攻击 IP 数、成功登录，以及近 14 天失败趋势。

## 配置 `/etc/sshshield/config.json`

```json
{
  "max_retry": 5,            // find_time 内失败几次封禁
  "find_time": "10m",
  "ban_time": "1h",          // 首次封禁时长
  "ban_time_factor": 2,      // 再犯倍数：1h → 2h → 4h ...
  "max_ban_time": "168h",    // 封顶
  "ignore_ip": ["127.0.0.0/8", "::1"],   // 白名单，支持 CIDR；只免封禁，仍照常计数
  "ports": [],               // 为空 = 封禁该 IP 全部流量；如 [22] 只封 SSH 端口
  "source": "auto",          // auto | journal | file
  "log_file": "",            // source=file 时的日志路径，默认自动找 auth.log / secure
  "backend": "auto",         // auto | nftables | iptables | none(只统计不封)
  "socket": "/run/sshshield.sock",
  "state_dir": "/var/lib/sshshield",
  "forget_after": "720h"     // 超过此时长无活动且未封禁的 IP 记录会被清理（全局总数保留）
}
```

（JSON 不支持注释，上面只是说明。）修改后 `systemctl restart sshshield`。

## 计数规则

计为一次失败：密码错误、不存在的用户、超过最大认证次数、`AllowUsers` 拒绝、未完成认证即断开（有效用户名），
以及扫描器行为（无 SSH 标识串、错误 banner、算法协商失败）。同一次尝试产生的多行日志只计一次
（如 `Invalid user` + `Failed password for invalid user`）。成功登录单独计数，不影响封禁。

## 数据

- `/var/lib/sshshield/state.json`：每 IP 记录 + 全局统计，每 15 秒及退出时落盘，重启后自动恢复仍在有效期的封禁。
- `/var/lib/sshshield/events.log`：所有失败/成功/封禁/解封事件（JSON Lines），超过 20MB 轮转为 `.1`。

nftables 模式下封禁写在独立的 `inet sshshield` 表里并带超时，即使守护进程意外退出，封禁也会按时自动过期；
服务停止时会删除该表。

## 构建

```bash
./build.sh v0.1.0   # 输出 dist/sshshield-linux-{amd64,arm64} 和 dist/sshshield-v0.1.0.tar.gz
```
