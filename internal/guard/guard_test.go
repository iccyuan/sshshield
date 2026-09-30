package guard

import (
	"testing"
	"time"

	"github.com/iccyuan/sshshield/internal/config"
	"github.com/iccyuan/sshshield/internal/firewall"
	"github.com/iccyuan/sshshield/internal/parser"
)

func newGuard(t *testing.T) *Guard {
	t.Helper()
	cfg := config.Default()
	cfg.MaxRetry = 3
	cfg.StateDir = t.TempDir()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	fw, _ := firewall.New("none", nil)
	g, err := New(cfg, "", fw, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g
}

func ev(line string) parser.Event {
	e, ok := parser.Parse(line)
	if !ok {
		panic(line)
	}
	return e
}

func TestBanAfterMaxRetry(t *testing.T) {
	g := newGuard(t)
	fail := ev("Failed password for root from 1.2.3.4 port 1 ssh2")
	soft := ev("Connection closed by authenticating user root 1.2.3.4 port 1 [preauth]")
	g.Handle(fail)
	g.Handle(soft) // same attempt, must not double count
	g.Handle(fail)
	r := g.st.Records["1.2.3.4"]
	if r.Failures != 2 || r.Banned(time.Now()) {
		t.Fatalf("after 2 failures: failures=%d banned=%v", r.Failures, r.Banned(time.Now()))
	}
	g.Handle(fail)
	if !r.Banned(time.Now()) || r.BanCount != 1 || g.st.Stats.TotalBans != 1 {
		t.Fatalf("expected ban, got %+v", r)
	}
	if d := r.BannedUntil.Sub(r.BannedAt); d != time.Hour {
		t.Fatalf("first ban %s, want 1h", d)
	}
	if g.banDuration(1) != 2*time.Hour || g.banDuration(4) != 16*time.Hour || g.banDuration(5) != Permanent {
		t.Fatal("escalation wrong")
	}

	if err := g.ManualUnban("1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if r.Banned(time.Now()) {
		t.Fatal("still banned")
	}
	if g.st.Stats.TotalFailures != 3 {
		t.Fatalf("total failures %d", g.st.Stats.TotalFailures)
	}
}

func TestIgnoredAndPersist(t *testing.T) {
	g := newGuard(t)
	for range 5 {
		g.Handle(ev("Invalid user x from 127.0.0.1 port 1"))
	}
	lo := g.st.Records["127.0.0.1"]
	if lo == nil || lo.Failures != 5 || lo.Banned(time.Now()) {
		t.Fatalf("whitelisted IP must be counted but never banned: %+v", lo)
	}
	g.Handle(ev("Invalid user admin from 5.5.5.5 port 1"))
	g.Handle(ev("Accepted publickey for bob from 6.6.6.6 port 1 ssh2: x"))
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	g2, err := New(g.cfg, "", g.fw, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	s := g2.Snapshot()
	if s.Stats.TotalFailures != 6 || s.Stats.TotalSuccesses != 1 || s.UniqueIPs != 3 || s.Stats.Users["admin"] != 1 {
		t.Fatalf("persisted stats wrong: %+v", s.Stats)
	}
}

func TestWhitelistEdit(t *testing.T) {
	g := newGuard(t)
	g.cfgPath = t.TempDir() + "/config.json"
	fail := ev("Failed password for root from 7.7.7.7 port 1 ssh2")
	for range 3 {
		g.Handle(fail)
	}
	if !g.st.Records["7.7.7.7"].Banned(time.Now()) {
		t.Fatal("expected ban")
	}
	if _, err := g.WhitelistAdd("7.7.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if g.st.Records["7.7.7.7"].Banned(time.Now()) {
		t.Fatal("whitelisting should lift the ban")
	}
	if _, err := g.WhitelistAdd("7.7.1.2/16"); err == nil {
		t.Fatal("duplicate network accepted")
	}
	if err := g.ManualBan("7.7.7.7", 0); err == nil {
		t.Fatal("banned a whitelisted IP")
	}
	c, err := config.Load(g.cfgPath)
	if err != nil || !c.Ignored(parser.NormalizeIP("7.7.9.9")) {
		t.Fatalf("whitelist not persisted: %v", err)
	}
	if _, err := g.WhitelistDel("7.7.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.WhitelistDel("7.7.0.0/16"); err == nil {
		t.Fatal("deleting missing entry succeeded")
	}
}

func TestPermanentBan(t *testing.T) {
	g := newGuard(t)
	g.cfg.PermAfter = 1
	g.cfg.ForgetAfter = config.Duration(time.Nanosecond)
	fail := ev("Failed password for root from 8.8.8.8 port 1 ssh2")
	for range 3 {
		g.Handle(fail)
	}
	r := g.st.Records["8.8.8.8"]
	if r.Permanent || !r.Banned(time.Now()) {
		t.Fatalf("first ban should be timed: %+v", r)
	}
	if err := g.ManualUnban("8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		g.Handle(fail)
	}
	if !r.Permanent || !r.BannedUntil.IsZero() {
		t.Fatalf("second ban should be permanent (perm_after=1): %+v", r)
	}
	r.LastSeen = time.Now().Add(-time.Hour)
	g.Tick()
	if g.st.Records["8.8.8.8"] != r || !r.Banned(time.Now()) {
		t.Fatal("tick expired or forgot a permanent ban")
	}
	if s := g.Snapshot(); s.Perm != 1 || s.Active != 1 {
		t.Fatalf("snapshot perm=%d active=%d", s.Perm, s.Active)
	}

	if err := g.ManualBan("9.9.9.9", Permanent); err != nil {
		t.Fatal(err)
	}
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	g2, err := New(g.cfg, "", g.fw, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if r := g2.st.Records["9.9.9.9"]; r == nil || !r.Permanent || !r.Manual {
		t.Fatalf("permanent ban not persisted: %+v", r)
	}
	if err := g2.ManualUnban("9.9.9.9"); err != nil || g2.st.Records["9.9.9.9"].Banned(time.Now()) {
		t.Fatalf("unban permanent: %v", err)
	}
}

func TestPasswordCapture(t *testing.T) {
	g := newGuard(t)
	fail := ev("Failed password for root from 3.3.3.3 port 1 ssh2")

	// Captured, then sshd logs the failure: recorded.
	_ = g.PasswordAttempt("3.3.3.3", "root", "123456")
	g.Handle(fail)
	// Captured, then the login succeeds: must be dropped.
	_ = g.PasswordAttempt("3.3.3.3", "root", "correct-horse")
	g.Handle(ev("Accepted password for root from 3.3.3.3 port 1 ssh2"))
	g.Handle(fail)
	// Whitelisted IPs are never recorded.
	_ = g.PasswordAttempt("127.0.0.1", "root", "admin-typo")
	g.Handle(ev("Failed password for root from 127.0.0.1 port 1 ssh2"))
	// Control characters are escaped.
	_ = g.PasswordAttempt("3.3.3.3", "root", "a\x1b[2Jb")
	g.Handle(fail)

	s := g.Snapshot()
	want := map[string]int64{"123456": 1, `a\x1b[2Jb`: 1}
	if len(s.Stats.Passwords) != len(want) || s.Stats.TotalPasswords != 2 {
		t.Fatalf("passwords %v total %d", s.Stats.Passwords, s.Stats.TotalPasswords)
	}
	for k, v := range want {
		if s.Stats.Passwords[k] != v {
			t.Fatalf("passwords %v, want %v", s.Stats.Passwords, want)
		}
	}
	if r := g.st.Records["3.3.3.3"]; r.Passwords["123456"] != 1 || r.Passwords["correct-horse"] != 0 {
		t.Fatalf("per-IP passwords %v", r.Passwords)
	}
	if len(g.pending) != 0 {
		t.Fatalf("pending not drained: %v", g.pending)
	}
}

func TestIsSSHDFakePassword(t *testing.T) {
	for pw, want := range map[string]bool{
		"\b\n\r\x7fIN":                    true, // 6-char password
		"\b\n\r\x7fINCORRECT":             true,
		"\b\n\r\x7fINCORRECT\b\n\r\x7fIN": true, // longer than the junk
		"123456":                          false,
		"":                                false,
		"\b\n\r\x7fINCORRECTx":            false,
	} {
		if got := IsSSHDFakePassword(pw); got != want {
			t.Errorf("IsSSHDFakePassword(%q) = %v, want %v", pw, got, want)
		}
	}
}
