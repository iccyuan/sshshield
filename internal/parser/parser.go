// Package parser turns sshd log lines into authentication events.
package parser

import (
	"net"
	"regexp"
)

type Kind int

const (
	// Fail is a definite failed attempt (bad password, invalid user, scanner probe...).
	Fail Kind = iota + 1
	// SoftFail is a preauth disconnect of a valid user; it usually follows a Fail
	// for the same attempt, so the guard only counts it when no Fail came just before.
	SoftFail
	Success
)

func (k Kind) String() string {
	switch k {
	case Fail, SoftFail:
		return "fail"
	case Success:
		return "success"
	}
	return "unknown"
}

type Event struct {
	Kind   Kind
	IP     net.IP
	User   string
	Reason string
}

type rule struct {
	re     *regexp.Regexp
	kind   Kind
	reason string
	userAt int // submatch index of user, 0 = none
	ipAt   int
	// skipAt: if this submatch is non-empty the line is ignored (already counted elsewhere).
	skipAt int
}

var rules = []rule{
	{re(`Accepted (\S+) for (\S+) from (\S+) port \d+`), Success, "accepted", 2, 3, 0},
	// "Failed password for invalid user x" is preceded by "Invalid user x", which is counted instead.
	{re(`Failed (?:password|keyboard-interactive/pam|publickey|none) for (invalid user )?(\S*) from (\S+) port \d+`), Fail, "bad password", 2, 3, 1},
	{re(`Invalid user (.*?) from (\S+?)(?: port \d+)?\s*$`), Fail, "invalid user", 1, 2, 0},
	{re(`maximum authentication attempts exceeded for (?:invalid user )?(\S*) from (\S+) port \d+`), Fail, "max auth attempts", 1, 2, 0},
	{re(`User (\S+) from (\S+) not allowed because`), Fail, "user not allowed", 1, 2, 0},
	{re(`(?:Connection closed|Disconnected) by authenticating user (\S+) (\S+) port \d+ \[preauth\]`), SoftFail, "preauth disconnect", 1, 2, 0},
	{re(`Did not receive identification string from (\S+)`), Fail, "no ident (scanner)", 0, 1, 0},
	{re(`banner exchange: Connection from (\S+) port \d+: invalid format`), Fail, "bad banner (scanner)", 0, 1, 0},
	{re(`Bad protocol version identification .* from (\S+)`), Fail, "bad protocol (scanner)", 0, 1, 0},
	{re(`Unable to negotiate with (\S+) port \d+`), Fail, "negotiation failed", 0, 1, 0},
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// Parse returns the event in line, or ok=false if the line is not relevant.
func Parse(line string) (Event, bool) {
	for _, r := range rules {
		m := r.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if r.skipAt > 0 && m[r.skipAt] != "" {
			return Event{}, false
		}
		ip := NormalizeIP(m[r.ipAt])
		if ip == nil {
			continue
		}
		ev := Event{Kind: r.kind, IP: ip, Reason: r.reason}
		if r.userAt > 0 {
			ev.User = m[r.userAt]
		}
		if r.kind == Success {
			ev.Reason = "accepted " + m[1]
		}
		return ev, true
	}
	return Event{}, false
}

// NormalizeIP parses s and folds IPv4-mapped IPv6 addresses to plain IPv4.
func NormalizeIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
