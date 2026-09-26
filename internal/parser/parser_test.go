package parser

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		kind Kind
		ip   string
		user string
	}{
		{"Failed password for root from 1.2.3.4 port 5022 ssh2", true, Fail, "1.2.3.4", "root"},
		{"Sep 26 10:00:00 host sshd[123]: Failed password for root from 1.2.3.4 port 5022 ssh2", true, Fail, "1.2.3.4", "root"},
		{"Failed password for invalid user admin from 1.2.3.4 port 5022 ssh2", false, 0, "", ""},
		{"Invalid user admin from 5.6.7.8 port 40000", true, Fail, "5.6.7.8", "admin"},
		{"Invalid user  from 5.6.7.8 port 40000", true, Fail, "5.6.7.8", ""},
		{"Invalid user oracle from 2001:db8::1", true, Fail, "2001:db8::1", "oracle"},
		{"Connection closed by authenticating user root 9.9.9.9 port 1234 [preauth]", true, SoftFail, "9.9.9.9", "root"},
		{"Disconnected from invalid user test 9.9.9.9 port 1234 [preauth]", false, 0, "", ""},
		{"Connection closed by invalid user test 9.9.9.9 port 1234 [preauth]", false, 0, "", ""},
		{"error: maximum authentication attempts exceeded for invalid user pi from 8.8.4.4 port 22 ssh2 [preauth]", true, Fail, "8.8.4.4", "pi"},
		{"Did not receive identification string from 10.1.1.1 port 999", true, Fail, "10.1.1.1", ""},
		{"banner exchange: Connection from 10.1.1.2 port 999: invalid format", true, Fail, "10.1.1.2", ""},
		{"Unable to negotiate with 10.1.1.3 port 999: no matching key exchange method found.", true, Fail, "10.1.1.3", ""},
		{"Accepted publickey for alice from ::ffff:1.1.1.1 port 22 ssh2: ED25519 SHA256:x", true, Success, "1.1.1.1", "alice"},
		{"Received disconnect from 1.2.3.4 port 5: 11: Bye Bye [preauth]", false, 0, "", ""},
	}
	for _, c := range cases {
		ev, ok := Parse(c.line)
		if ok != c.ok {
			t.Errorf("%q: ok=%v want %v", c.line, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if ev.Kind != c.kind || ev.IP.String() != c.ip || ev.User != c.user {
			t.Errorf("%q: got kind=%v ip=%s user=%q", c.line, ev.Kind, ev.IP, ev.User)
		}
	}
}
