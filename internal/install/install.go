// Package install sets sshshield up as a systemd service in one step.
package install

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/iccyuan/sshshield/internal/config"
	"github.com/iccyuan/sshshield/internal/firewall"
)

const (
	BinPath  = "/usr/local/bin/sshshield"
	UnitPath = "/etc/systemd/system/sshshield.service"
)

const unit = `[Unit]
Description=SSHShield - SSH brute-force protection
Documentation=https://github.com/iccyuan/sshshield
After=network.target nftables.service firewalld.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sshshield run -c %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`

func checkRoot() error {
	if runtime.GOOS != "linux" {
		return errors.New("install is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("please run as root (sudo sshshield install)")
	}
	return nil
}

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func Install(cfgPath string) error {
	if err := checkRoot(); err != nil {
		return err
	}
	step := func(s string) { fmt.Printf("\033[1;34m==>\033[0m %s\n", s) }

	step("安装二进制到 " + BinPath)
	if err := copySelf(BinPath); err != nil {
		return err
	}

	if !have("nft") && !have("iptables") {
		step("未找到 nft/iptables，尝试安装 nftables")
		if err := installPkg("nftables"); err != nil {
			return fmt.Errorf("install nftables: %w", err)
		}
	}

	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		step("生成配置 " + cfgPath)
		cfg := config.Default()
		admins := adminIPs()
		for _, ip := range admins {
			cfg.IgnoreIP = append(cfg.IgnoreIP, ip)
		}
		if len(admins) > 0 {
			fmt.Printf("    已把当前登录的管理 IP 加入白名单: %s\n", strings.Join(admins, ", "))
		}
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
			return err
		}
		if err := cfg.Save(cfgPath); err != nil {
			return err
		}
	} else {
		step("保留现有配置 " + cfgPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if _, err := firewall.New(cfg.Backend, cfg.Ports); err != nil {
		return err
	}

	if !have("systemctl") {
		fmt.Println("\n未检测到 systemd，请自行以守护方式运行:\n  " + BinPath + " run -c " + cfgPath)
		return nil
	}
	step("写入 systemd 服务 " + UnitPath)
	if err := os.WriteFile(UnitPath, []byte(fmt.Sprintf(unit, cfgPath)), 0o644); err != nil {
		return err
	}
	_ = sh("systemctl", "daemon-reload")
	step("启用并启动服务")
	if err := sh("systemctl", "enable", "sshshield"); err != nil {
		return err
	}
	if err := sh("systemctl", "restart", "sshshield"); err != nil {
		return err
	}
	fmt.Print("\n\033[32m✓ SSHShield 已安装并运行\033[0m\n")
	fmt.Printf(`  查看面板:  sudo sshshield            (TUI)
  文字状态:  sudo sshshield status
  手动封禁:  sudo sshshield ban <IP> [时长]
  解除封禁:  sudo sshshield unban <IP>
  配置文件:  %s  (改完执行 systemctl restart sshshield)
  服务日志:  journalctl -u sshshield -f
`, cfgPath)
	return nil
}

func Uninstall(cfgPath string, purge bool) error {
	if err := checkRoot(); err != nil {
		return err
	}
	cfg, _ := config.Load(cfgPath)
	if have("systemctl") {
		_ = exec.Command("systemctl", "disable", "--now", "sshshield").Run()
		_ = os.Remove(UnitPath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	// The daemon removes its rules on stop; do it again in case it was not running.
	if cfg != nil {
		if fw, err := firewall.New(cfg.Backend, cfg.Ports); err == nil {
			_ = fw.Teardown()
		}
	}
	_ = os.Remove(BinPath)
	if purge {
		_ = os.RemoveAll(filepath.Dir(cfgPath))
		if cfg != nil {
			_ = os.RemoveAll(cfg.StateDir)
		}
		fmt.Println("✓ 已卸载并清除配置与统计数据")
	} else {
		fmt.Println("✓ 已卸载（配置与统计数据保留，加 --purge 可一并删除）")
	}
	return nil
}

func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src, err = filepath.EvalSymlinks(src); err != nil {
		return err
	}
	if abs, _ := filepath.Abs(dst); abs == src {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Rename so a running old binary is replaced safely.
	return os.Rename(tmp, dst)
}

func installPkg(pkg string) error {
	switch {
	case have("apt-get"):
		_ = sh("apt-get", "update", "-qq")
		return sh("apt-get", "install", "-y", "-qq", pkg)
	case have("dnf"):
		return sh("dnf", "install", "-y", pkg)
	case have("yum"):
		return sh("yum", "install", "-y", pkg)
	case have("apk"):
		return sh("apk", "add", pkg)
	case have("pacman"):
		return sh("pacman", "-S", "--noconfirm", pkg)
	}
	return errors.New("no supported package manager found")
}

var whoIP = regexp.MustCompile(`\(([0-9a-fA-F:.]+)\)`)

// adminIPs returns the remote IPs of current SSH sessions so the installer
// never locks out the person running it.
func adminIPs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
	}
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if f := strings.Fields(os.Getenv(env)); len(f) > 0 {
			add(f[0])
		}
	}
	if b, err := exec.Command("who").Output(); err == nil {
		for _, m := range whoIP.FindAllStringSubmatch(string(b), -1) {
			add(m[1])
		}
	}
	return out
}
