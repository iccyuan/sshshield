package tui

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iccyuan/sshshield/internal/guard"
)

func frameOut(t *testing.T, s *screen, frame string) string {
	t.Helper()
	var buf bytes.Buffer
	s.out = &buf
	if err := s.render(frame); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestScreenWritesOnlyChangedCells(t *testing.T) {
	s := &screen{}
	s.resize(60, 3)
	row := func(left string) string {
		return "\x1b[31m 103.137.184.170  已封禁 \x1b[m 剩余 " + left + " 监视中"
	}
	frameOut(t, s, "标题\n"+row("3h31m49s")+"\n底栏")
	out := frameOut(t, s, "标题\n"+row("3h31m48s")+"\n底栏")

	if strings.Contains(out, "103.137") || strings.Contains(out, "标题") || strings.Contains(out, "底栏") {
		t.Fatalf("unchanged text was rewritten: %q", out)
	}
	if !strings.Contains(out, "8") || strings.Contains(out, "\x1b[K") || strings.Contains(out, "\x1b[2J") {
		t.Fatalf("expected only the changed digit and no erase: %q", out)
	}
	if again := frameOut(t, s, "标题\n"+row("3h31m48s")+"\n底栏"); again != "" {
		t.Fatalf("identical frame produced output: %q", again)
	}
}

func TestScreenWideCharBoundaries(t *testing.T) {
	s := &screen{}
	s.resize(20, 1)
	frameOut(t, s, "ab监视中cd")
	// 视 -> 封 changes one wide character: the whole character must be rewritten
	// starting at its head column (col 5, 1-based), never half of it.
	out := frameOut(t, s, "ab监封中cd")
	if !strings.Contains(out, "\x1b[1;5H") || !strings.Contains(out, "封") || strings.Contains(out, "监") || strings.Contains(out, "中") {
		t.Fatalf("wide span wrong: %q", out)
	}
	// Narrow text replacing a wide character must cover both of its columns.
	out = frameOut(t, s, "ab监xy中cd")
	if !strings.Contains(out, "\x1b[1;5H\x1b[mxy") {
		t.Fatalf("narrow-over-wide span wrong: %q", out)
	}
	// And a wide character replacing narrow text starts at its own head.
	out = frameOut(t, s, "ab监封中cd")
	if !strings.Contains(out, "\x1b[1;5H") || !strings.Contains(out, "封") {
		t.Fatalf("wide-over-narrow span wrong: %q", out)
	}
}

func TestDecodeInput(t *testing.T) {
	evs, rest := decodeInput([]byte("q\x1b[A\x1b[Z\x1b[6~\r\x7f中\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b"))
	var names []string
	for _, e := range evs {
		switch v := e.(type) {
		case key:
			names = append(names, v.name)
		case bgMsg:
			if v.dark {
				t.Fatal("white background reported as dark")
			}
			names = append(names, "bg")
		}
	}
	want := "q up shift+tab pgdown enter backspace 中 bg esc"
	if got := strings.Join(names, " "); got != want || rest != nil {
		t.Fatalf("got %q rest %q, want %q", got, rest, want)
	}
	// An incomplete CSI sequence is kept for the next read.
	if evs, rest := decodeInput([]byte("\x1b[")); len(evs) != 0 || string(rest) != "\x1b[" {
		t.Fatalf("partial sequence: %v %q", evs, rest)
	}
}

func TestScreenSkipsUnchangedMiddle(t *testing.T) {
	s := &screen{}
	s.resize(80, 1)
	// An IP between two ticking values: a single first-to-last span would
	// rewrite it, which makes Termius flash its IP highlight.
	line := func(a, b string) string { return "失败 " + a + "  来源 203.0.113.170 已封禁  剩余 " + b }
	frameOut(t, s, line("12", "59s"))
	out := frameOut(t, s, line("13", "58s"))
	if strings.Contains(out, "203.0.113") {
		t.Fatalf("IP between two changes was rewritten: %q", out)
	}
	if !strings.Contains(out, "3") || !strings.Contains(out, "8") {
		t.Fatalf("changed digits missing: %q", out)
	}
}

// Moving the selection must never rewrite an IP (Termius flashes its IP
// highlight on each rewrite), must touch only the two affected rows, and must
// not wrap the selected row onto a second line on narrow terminals.
func TestSelectionLeavesIPsUntouched(t *testing.T) {
	now := time.Now()
	s := &guard.Snapshot{Now: now, Started: now, Stats: guard.Stats{Users: map[string]int64{}, DailyFailures: map[string]int64{}}}
	for i := range 4 {
		ip := fmt.Sprintf("203.0.113.%d", 10+i)
		s.Records = append(s.Records, &guard.IPRecord{IP: ip, Failures: int64(100 - i), LastSeen: now,
			BannedUntil: now.Add(time.Hour), Users: map[string]int64{"root": 3}})
		s.Recent = append(s.Recent, guard.Event{Time: now, IP: ip, User: "root", Type: "fail", Reason: "bad password"})
	}
	s.Records[0].Permanent = true
	rowRe := regexp.MustCompile(`\[(\d+);\d+H`)
	for _, tb := range []tab{tabBanned, tabAttackers, tabEvents} {
		for _, w := range []int{80, 160} {
			m := &model{snap: s, w: w, h: 30, tab: tb}
			scr := &screen{}
			scr.resize(m.w, m.h)
			frameOut(t, scr, m.render())
			m.move(1, len(m.rows()))
			out := frameOut(t, scr, m.render())
			if strings.Contains(out, "203.0.113") {
				t.Errorf("tab %d w=%d: IP rewritten: %q", tb, w, out)
			}
			ys := map[string]bool{}
			for _, mm := range rowRe.FindAllStringSubmatch(out, -1) {
				ys[mm[1]] = true
			}
			if len(ys) != 2 {
				t.Errorf("tab %d w=%d: rows %v rewritten, want 2: %q", tb, w, ys, out)
			}
		}
	}
}
