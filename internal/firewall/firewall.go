// Package firewall applies bans through nftables or iptables.
package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Backend interface {
	Name() string
	Setup() error
	Ban(ip net.IP, d time.Duration) error
	Unban(ip net.IP) error
	Teardown() error
	// Check reports an error if our rules vanished (e.g. firewalld --reload flushed them).
	Check() error
}

func New(name string, ports []int) (Backend, error) {
	switch name {
	case "", "auto":
		if _, err := exec.LookPath("nft"); err == nil {
			return &nft{ports: ports}, nil
		}
		if _, err := exec.LookPath("iptables"); err == nil {
			return &ipt{ports: ports}, nil
		}
		return nil, fmt.Errorf("neither nft nor iptables found; install nftables or set backend to \"none\"")
	case "nftables", "nft":
		return &nft{ports: ports}, nil
	case "iptables":
		return &ipt{ports: ports}, nil
	case "none":
		return none{}, nil
	}
	return nil, fmt.Errorf("unknown backend %q", name)
}

func run(name string, stdin string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func portList(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

// ---- nftables: one dedicated table with timed sets, so bans expire even if the daemon dies.

const nftTable = "sshshield"

type nft struct{ ports []int }

func (n *nft) Name() string { return "nftables" }

func (n *nft) Setup() error {
	match := "drop"
	if len(n.ports) > 0 {
		match = "tcp dport { " + portList(n.ports) + " } drop"
	}
	script := fmt.Sprintf(`table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
	set banned4 { type ipv4_addr; flags timeout; }
	set banned6 { type ipv6_addr; flags timeout; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @banned4 %[2]s
		ip6 saddr @banned6 %[2]s
	}
}
`, nftTable, match)
	return run("nft", script, "-f", "-")
}

func nftSet(ip net.IP) string {
	if ip.To4() != nil {
		return "banned4"
	}
	return "banned6"
}

func (n *nft) Ban(ip net.IP, d time.Duration) error {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	// Re-adding an existing element fails, so drop any old one first.
	_ = n.Unban(ip)
	return run("nft", "", "add", "element", "inet", nftTable, nftSet(ip),
		fmt.Sprintf("{ %s timeout %ds }", ip, secs))
}

func (n *nft) Unban(ip net.IP) error {
	return run("nft", "", "delete", "element", "inet", nftTable, nftSet(ip), fmt.Sprintf("{ %s }", ip))
}

func (n *nft) Check() error {
	return run("nft", "", "list", "chain", "inet", nftTable, "input")
}

func (n *nft) Teardown() error {
	return run("nft", "", "delete", "table", "inet", nftTable)
}

// ---- iptables / ip6tables: a dedicated chain jumped to from INPUT.

const iptChain = "SSHSHIELD"

type ipt struct{ ports []int }

func (t *ipt) Name() string { return "iptables" }

func (t *ipt) tools() []string {
	tools := []string{"iptables"}
	if _, err := exec.LookPath("ip6tables"); err == nil {
		tools = append(tools, "ip6tables")
	}
	return tools
}

func (t *ipt) Setup() error {
	for _, tool := range t.tools() {
		_ = run(tool, "", "-w", "-N", iptChain)
		if err := run(tool, "", "-w", "-F", iptChain); err != nil {
			return err
		}
		if run(tool, "", "-w", "-C", "INPUT", "-j", iptChain) != nil {
			if err := run(tool, "", "-w", "-I", "INPUT", "1", "-j", iptChain); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *ipt) spec(ip net.IP) (string, []string) {
	tool := "iptables"
	if ip.To4() == nil {
		tool = "ip6tables"
	}
	args := []string{"-s", ip.String()}
	if len(t.ports) > 0 {
		args = append(args, "-p", "tcp", "-m", "multiport", "--dports", portList(t.ports))
	}
	return tool, append(args, "-j", "DROP")
}

func (t *ipt) Ban(ip net.IP, _ time.Duration) error {
	tool, spec := t.spec(ip)
	if run(tool, "", append([]string{"-w", "-C", iptChain}, spec...)...) == nil {
		return nil
	}
	return run(tool, "", append([]string{"-w", "-I", iptChain}, spec...)...)
}

func (t *ipt) Unban(ip net.IP) error {
	tool, spec := t.spec(ip)
	return run(tool, "", append([]string{"-w", "-D", iptChain}, spec...)...)
}

func (t *ipt) Check() error {
	for _, tool := range t.tools() {
		if err := run(tool, "", "-w", "-C", "INPUT", "-j", iptChain); err != nil {
			return err
		}
	}
	return nil
}

func (t *ipt) Teardown() error {
	var first error
	for _, tool := range t.tools() {
		for run(tool, "", "-w", "-D", "INPUT", "-j", iptChain) == nil {
		}
		_ = run(tool, "", "-w", "-F", iptChain)
		if err := run(tool, "", "-w", "-X", iptChain); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ---- none: detection only.

type none struct{}

func (none) Name() string                    { return "none" }
func (none) Setup() error                    { return nil }
func (none) Ban(net.IP, time.Duration) error { return nil }
func (none) Unban(net.IP) error              { return nil }
func (none) Teardown() error                 { return nil }
func (none) Check() error                    { return nil }
