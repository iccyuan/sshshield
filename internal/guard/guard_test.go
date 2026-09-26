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
	g, err := New(cfg, fw, "test")
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
	if g.banDuration(1) != 2*time.Hour || g.banDuration(20) != 7*24*time.Hour {
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
	if len(g.st.Records) != 0 {
		t.Fatal("loopback should be ignored")
	}
	g.Handle(ev("Invalid user admin from 5.5.5.5 port 1"))
	g.Handle(ev("Accepted publickey for bob from 6.6.6.6 port 1 ssh2: x"))
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	g2, err := New(g.cfg, g.fw, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	s := g2.Snapshot()
	if s.Stats.TotalFailures != 1 || s.Stats.TotalSuccesses != 1 || s.UniqueIPs != 2 || s.Stats.Users["admin"] != 1 {
		t.Fatalf("persisted stats wrong: %+v", s.Stats)
	}
}
