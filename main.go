// Command sshshield protects sshd from brute-force attacks.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/iccyuan/sshshield/internal/api"
	"github.com/iccyuan/sshshield/internal/config"
	"github.com/iccyuan/sshshield/internal/firewall"
	"github.com/iccyuan/sshshield/internal/guard"
	"github.com/iccyuan/sshshield/internal/install"
	"github.com/iccyuan/sshshield/internal/parser"
	"github.com/iccyuan/sshshield/internal/source"
	"github.com/iccyuan/sshshield/internal/tui"
)

var version = "dev"

const usage = `SSHShield - SSH 暴力破解防护

用法:
  sshshield                      打开 TUI 面板（同 tui）
  sshshield tui                  打开 TUI 面板
  sshshield status               打印统计与封禁列表
  sshshield ban <IP> [时长]      手动封禁，如 ban 1.2.3.4 24h；时长写 perm 为永久封禁
  sshshield unban <IP>           解除封禁
  sshshield allow <IP|网段>      加入白名单（永不封禁，已封禁的会解封）
  sshshield disallow <IP|网段>   移出白名单
  sshshield pam on|off|status    记录攻击者尝试的密码（在 /etc/pam.d/sshd 加 pam_exec 钩子）
  sshshield run                  以守护进程运行（systemd 调用）
  sshshield install              一键安装为 systemd 服务
  sshshield uninstall [--purge]  卸载（--purge 同时删除配置与数据）
  sshshield version

通用参数:
  -c <路径>   配置文件（默认 /etc/sshshield/config.json）
`

func main() {
	args := os.Args[1:]
	cmd := "tui"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := fs.String("c", config.DefaultPath, "config file")
	purge := fs.Bool("purge", false, "uninstall: also remove config and data")
	// Accept flags before or after positional args (e.g. "ban 1.2.3.4 -c x.json").
	var rest []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}

	var err error
	switch cmd {
	case "pam-hook":
		pamHook(*cfgPath) // called by pam_exec on every login attempt; must never fail loudly
		return
	case "pam":
		if len(rest) < 1 {
			fs.Usage()
			os.Exit(2)
		}
		err = pamCmd(rest[0])
	case "run":
		err = runDaemon(*cfgPath)
	case "tui":
		err = withSocket(*cfgPath, tui.Run)
	case "status":
		err = withSocket(*cfgPath, status)
	case "ban", "unban", "allow", "disallow":
		if len(rest) < 1 {
			fs.Usage()
			os.Exit(2)
		}
		req := api.Request{Cmd: cmd, IP: rest[0]}
		if cmd == "ban" && len(rest) > 1 {
			req.Duration = rest[1]
		}
		err = withSocket(*cfgPath, func(sock string) error {
			resp, err := api.Call(sock, req)
			if err != nil {
				return err
			}
			if resp.Message != "" {
				fmt.Println("✓", resp.Message)
			} else {
				fmt.Printf("✓ %s %s\n", cmd, req.IP)
			}
			return nil
		})
	case "install":
		err = install.Install(*cfgPath)
	case "uninstall":
		err = install.Uninstall(*cfgPath, *purge)
	case "version":
		fmt.Println("sshshield", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", cmd)
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

// pamHook forwards one attempted password (stdin, from pam_exec expose_authtok)
// to the daemon. It stays silent and quick so it can never slow down or break logins.
func pamHook(cfgPath string) {
	if os.Getenv("PAM_TYPE") != "auth" {
		return
	}
	ip := os.Getenv("PAM_RHOST")
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	pw, _, _ := strings.Cut(string(b), "\x00")
	if ip == "" || pw == "" || guard.IsSSHDFakePassword(pw) {
		return
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return
	}
	_, _ = api.CallTimeout(cfg.Socket, api.Request{Cmd: "password", IP: ip, User: os.Getenv("PAM_USER"), Password: pw}, time.Second)
}

func pamCmd(action string) error {
	switch action {
	case "on":
		if err := install.PAMEnable(); err != nil {
			return err
		}
		fmt.Println("✓ 已开启密码记录（" + install.PAMFile + "），新的登录尝试立即生效")
		fmt.Println("  只记录登录失败的密码；白名单 IP 不记录；登录成功的密码会被丢弃")
		fmt.Println("  注意：只有允许密码登录的用户（sshd PasswordAuthentication）才能抓到密码")
		fmt.Println("  不存在的用户、以及 PermitRootLogin 不是 yes 时的 root，sshd 不会把真实密码交给 PAM，无法记录")
	case "off":
		if err := install.PAMDisable(); err != nil {
			return err
		}
		fmt.Println("✓ 已关闭密码记录（已记录的统计保留）")
	case "status":
		on, err := install.PAMEnabled()
		if err != nil {
			return err
		}
		if on {
			fmt.Println("密码记录: 已开启")
		} else {
			fmt.Println("密码记录: 未开启（sudo sshshield pam on 开启）")
		}
	default:
		return fmt.Errorf("用法: sshshield pam on|off|status")
	}
	return nil
}

func withSocket(cfgPath string, fn func(sock string) error) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	return fn(cfg.Socket)
}

func runDaemon(cfgPath string) error {
	log.SetFlags(0) // journald adds timestamps
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	kind, file, err := source.Resolve(cfg.Source, cfg.LogFile)
	if err != nil {
		return err
	}
	fw, err := firewall.New(cfg.Backend, cfg.Ports)
	if err != nil {
		return err
	}
	if err := fw.Setup(); err != nil {
		return fmt.Errorf("firewall setup: %w", err)
	}
	defer func() {
		if err := fw.Teardown(); err != nil {
			log.Printf("firewall teardown: %v", err)
		}
	}()

	srcDesc := kind
	if file != "" {
		srcDesc += ":" + file
	}
	g, err := guard.New(cfg, cfgPath, fw, srcDesc)
	if err != nil {
		return err
	}
	defer g.Close()
	g.RestoreBans()

	ln, err := api.Serve(cfg.Socket, g)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Socket, err)
	}
	defer func() { ln.Close(); os.Remove(cfg.Socket) }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lines := make(chan string, 1024)
	go source.Run(ctx, kind, file, lines)
	log.Printf("sshshield %s started: source=%s backend=%s max_retry=%d find_time=%s ban_time=%s",
		version, srcDesc, fw.Name(), cfg.MaxRetry, cfg.FindTime.D(), cfg.BanTime.D())

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	save := time.NewTicker(15 * time.Second)
	defer save.Stop()
	heal := time.NewTicker(30 * time.Second)
	defer heal.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case line := <-lines:
			if ev, ok := parser.Parse(line); ok {
				g.Handle(ev)
			}
		case <-tick.C:
			g.Tick()
		case <-heal.C:
			g.Heal()
		case <-save.C:
			if err := g.Save(); err != nil {
				log.Printf("save state: %v", err)
			}
		}
	}
}

func status(sock string) error {
	resp, err := api.Call(sock, api.Request{Cmd: "snapshot"})
	if err != nil {
		return err
	}
	s := resp.Snapshot
	today := s.Now.Format("2006-01-02")
	fmt.Printf("SSHShield  后端=%s  来源=%s  规则=%d次/%s → 封%s起  已运行 %s\n\n",
		s.Backend, s.Source, s.MaxRetry, s.FindTime, s.BanTime, s.Now.Sub(s.Started).Round(time.Second))
	fmt.Printf("总失败次数 %d   今日失败 %d   临时封禁 %d   永久封禁 %d   累计封禁 %d   攻击IP %d   成功登录 %d\n",
		s.Stats.TotalFailures, s.Stats.DailyFailures[today], s.Active, s.Perm, s.Stats.TotalBans, s.UniqueIPs, s.Stats.TotalSuccesses)

	var banned, top []*guard.IPRecord
	for _, r := range s.Records {
		if r.Banned(s.Now) {
			banned = append(banned, r)
		}
		if r.Failures > 0 {
			top = append(top, r)
		}
	}
	fmt.Printf("\n白名单: %s\n", strings.Join(s.Whitelist, ", "))
	fmt.Printf("\n当前封禁 (%d，含永久):\n", len(banned))
	for _, r := range banned {
		left := "永久"
		if !r.Permanent {
			left = r.BannedUntil.Sub(s.Now).Round(time.Second).String()
		}
		fmt.Printf("  %-40s 失败 %-6d 第%d次封禁  剩余 %s\n", r.IP, r.Failures, r.BanCount, left)
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Failures > top[j].Failures })
	if len(top) > 10 {
		top = top[:10]
	}
	fmt.Println("\n失败次数 Top 10:")
	for _, r := range top {
		fmt.Printf("  %-40s 失败 %-6d 封禁 %d 次  最后 %s\n", r.IP, r.Failures, r.BanCount, r.LastSeen.Local().Format("01-02 15:04"))
	}
	if len(s.Stats.Passwords) > 0 {
		type kv struct {
			k string
			v int64
		}
		var pws []kv
		for k, v := range s.Stats.Passwords {
			pws = append(pws, kv{k, v})
		}
		sort.Slice(pws, func(i, j int) bool {
			if pws[i].v != pws[j].v {
				return pws[i].v > pws[j].v
			}
			return pws[i].k < pws[j].k
		})
		fmt.Printf("\n尝试密码 Top 10（共捕获 %d 次）:\n", s.Stats.TotalPasswords)
		for _, e := range pws[:min(len(pws), 10)] {
			fmt.Printf("  %-32s %d 次\n", e.k, e.v)
		}
	}
	return nil
}
