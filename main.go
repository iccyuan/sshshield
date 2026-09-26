// Command sshshield protects sshd from brute-force attacks.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
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
  sshshield ban <IP> [时长]      手动封禁，如 ban 1.2.3.4 24h
  sshshield unban <IP>           解除封禁
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
	case "run":
		err = runDaemon(*cfgPath)
	case "tui":
		err = withSocket(*cfgPath, tui.Run)
	case "status":
		err = withSocket(*cfgPath, status)
	case "ban", "unban":
		if len(rest) < 1 {
			fs.Usage()
			os.Exit(2)
		}
		req := api.Request{Cmd: cmd, IP: rest[0]}
		if cmd == "ban" && len(rest) > 1 {
			req.Duration = rest[1]
		}
		err = withSocket(*cfgPath, func(sock string) error {
			if _, err := api.Call(sock, req); err != nil {
				return err
			}
			fmt.Printf("✓ %s %s\n", cmd, req.IP)
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
	g, err := guard.New(cfg, fw, srcDesc)
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
	fmt.Printf("总失败次数 %d   今日失败 %d   当前封禁 %d   累计封禁 %d   攻击IP %d   成功登录 %d\n",
		s.Stats.TotalFailures, s.Stats.DailyFailures[today], s.Active, s.Stats.TotalBans, s.UniqueIPs, s.Stats.TotalSuccesses)

	var banned, top []*guard.IPRecord
	for _, r := range s.Records {
		if r.Banned(s.Now) {
			banned = append(banned, r)
		}
		if r.Failures > 0 {
			top = append(top, r)
		}
	}
	fmt.Printf("\n当前封禁 (%d):\n", len(banned))
	for _, r := range banned {
		fmt.Printf("  %-40s 失败 %-6d 第%d次封禁  剩余 %s\n", r.IP, r.Failures, r.BanCount, r.BannedUntil.Sub(s.Now).Round(time.Second))
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Failures > top[j].Failures })
	if len(top) > 10 {
		top = top[:10]
	}
	fmt.Println("\n失败次数 Top 10:")
	for _, r := range top {
		fmt.Printf("  %-40s 失败 %-6d 封禁 %d 次  最后 %s\n", r.IP, r.Failures, r.BanCount, r.LastSeen.Local().Format("01-02 15:04"))
	}
	return nil
}
