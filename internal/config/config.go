// Package config loads and validates the sshshield configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const DefaultPath = "/etc/sshshield/config.json"

// Duration is a time.Duration that (un)marshals as a Go duration string ("10m", "1h").
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Also accept a bare number of seconds.
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"10m\": %w", err)
		}
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type Config struct {
	// Failures from one IP within FindTime that trigger a ban.
	MaxRetry int      `json:"max_retry"`
	FindTime Duration `json:"find_time"`
	// First ban length; each repeat ban is multiplied by BanTimeFactor, capped at MaxBanTime.
	BanTime       Duration `json:"ban_time"`
	BanTimeFactor float64  `json:"ban_time_factor"`
	MaxBanTime    Duration `json:"max_ban_time"`
	// IPs / CIDRs that are never banned.
	IgnoreIP []string `json:"ignore_ip"`
	// TCP ports to block for banned IPs; empty means drop all traffic from them.
	Ports []int `json:"ports"`
	// Log source: "auto", "journal" or "file".
	Source  string `json:"source"`
	LogFile string `json:"log_file"`
	// Firewall backend: "auto", "nftables", "iptables" or "none" (detect only).
	Backend  string `json:"backend"`
	Socket   string `json:"socket"`
	StateDir string `json:"state_dir"`
	// Forget idle, unbanned IP records after this long (global totals are kept).
	ForgetAfter Duration `json:"forget_after"`

	ignoreNets []*net.IPNet
}

func Default() *Config {
	return &Config{
		MaxRetry:      5,
		FindTime:      Duration(10 * time.Minute),
		BanTime:       Duration(time.Hour),
		BanTimeFactor: 2,
		MaxBanTime:    Duration(7 * 24 * time.Hour),
		IgnoreIP:      []string{"127.0.0.0/8", "::1"},
		Ports:         []int{},
		Source:        "auto",
		Backend:       "auto",
		Socket:        "/run/sshshield.sock",
		StateDir:      "/var/lib/sshshield",
		ForgetAfter:   Duration(30 * 24 * time.Hour),
	}
}

// Load reads path; a missing file yields the defaults.
func Load(path string) (*Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	if c.MaxRetry < 1 {
		return errors.New("max_retry must be >= 1")
	}
	if c.FindTime <= 0 || c.BanTime <= 0 {
		return errors.New("find_time and ban_time must be > 0")
	}
	if c.BanTimeFactor < 1 {
		c.BanTimeFactor = 1
	}
	if c.MaxBanTime < c.BanTime {
		c.MaxBanTime = c.BanTime
	}
	for _, p := range c.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}
	c.ignoreNets = nil
	for _, s := range c.IgnoreIP {
		n, err := ParseCIDROrIP(s)
		if err != nil {
			return fmt.Errorf("ignore_ip %q: %w", s, err)
		}
		c.ignoreNets = append(c.ignoreNets, n)
	}
	return nil
}

func (c *Config) Ignored(ip net.IP) bool {
	for _, n := range c.ignoreNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ParseCIDROrIP(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errors.New("not an IP or CIDR")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
