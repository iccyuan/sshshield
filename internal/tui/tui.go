// Package tui is the interactive terminal dashboard.
package tui

import (
	"fmt"
	"image/color"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/iccyuan/sshshield/internal/api"
	"github.com/iccyuan/sshshield/internal/config"
	"github.com/iccyuan/sshshield/internal/guard"
)

const refreshEvery = time.Second

var (
	cAccent, cRed, cGreen, cYellow, cMuted, cBorder, cSelBg                     color.Color
	sTitle, sMuted, sRed, sGreen, sYellow, sBold, sCard, sTabOn, sTabOff, sHead lipgloss.Style
)

func init() { setTheme(true) }

// setTheme builds the palette for a dark or light terminal background.
func setTheme(dark bool) {
	ld := lipgloss.LightDark(dark)
	cAccent = ld(lipgloss.Color("#0969da"), lipgloss.Color("#58a6ff"))
	cRed = ld(lipgloss.Color("#cf222e"), lipgloss.Color("#ff7b72"))
	cGreen = ld(lipgloss.Color("#1a7f37"), lipgloss.Color("#3fb950"))
	cYellow = ld(lipgloss.Color("#9a6700"), lipgloss.Color("#d29922"))
	cMuted = ld(lipgloss.Color("#6e7781"), lipgloss.Color("#8b949e"))
	cBorder = ld(lipgloss.Color("#d0d7de"), lipgloss.Color("#30363d"))
	cSelBg = ld(lipgloss.Color("#ddf4ff"), lipgloss.Color("#1f2d3d"))

	sTitle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sMuted = lipgloss.NewStyle().Foreground(cMuted)
	sRed = lipgloss.NewStyle().Foreground(cRed)
	sGreen = lipgloss.NewStyle().Foreground(cGreen)
	sYellow = lipgloss.NewStyle().Foreground(cYellow)
	sBold = lipgloss.NewStyle().Bold(true)
	sCard = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(0, 1)
	sTabOn = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")).Background(cAccent).Padding(0, 1)
	sTabOff = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 1)
	sHead = lipgloss.NewStyle().Bold(true).Foreground(cMuted)
}

type tab int

const (
	tabBanned tab = iota
	tabPermanent
	tabAttackers
	tabEvents
	tabUsers
	tabPasswords
	tabWhitelist
	tabCount
)

var tabNames = [...]string{"封禁中", "永久封禁", "攻击来源", "最近事件", "用户名排行", "密码排行", "白名单"}

type col struct {
	title string
	width int // 0 = take the remaining space
	right bool
}

type row struct {
	cells       []string
	key         string // stable identity for keeping the selection across refreshes; defaults to ip
	ip          string
	banned      bool
	whitelisted bool
	style       lipgloss.Style
}

type (
	snapMsg   struct{ s *guard.Snapshot }
	errMsg    struct{ err error }
	actionMsg struct {
		text string
		err  error
	}
	quitMsg struct{}
)

type (
	msg any
	cmd func() msg // runs off the UI goroutine; its result is fed back to update
)

func quit() msg { return quitMsg{} }

type model struct {
	sock    string
	snap    *guard.Snapshot
	err     error
	w, h    int
	tab     tab
	cursor  [tabCount]int
	sel     [tabCount]string // key of the selected row; the cursor follows it when rows reorder
	offset  [tabCount]int
	sortBy  int // attackers: 0 failures, 1 last seen, 2 bans
	filter  string
	editing bool
	adding  bool // typing a new whitelist entry
	addBuf  string
	confirm *pending
	status  string
	statusT time.Time
}

type pending struct {
	prompt string
	req    api.Request
}

func Run(sock string) error {
	in, out := os.Stdin, os.Stdout
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return fmt.Errorf("TUI 需要在终端中运行，非交互环境请用 sshshield status")
	}
	w, h, err := term.GetSize(int(out.Fd()))
	if err != nil {
		return err
	}
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return err
	}
	cw := colorprofile.NewWriter(out, os.Environ()) // downgrade colors to what the terminal supports
	// Alt screen, hidden cursor, no auto-wrap (so writing the last column never scrolls),
	// then ask for the background color (OSC 11) to pick the light or dark palette.
	_, _ = io.WriteString(out, "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b]11;?\x1b\\")
	defer func() {
		_, _ = io.WriteString(out, "\x1b[m\x1b[?7h\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), state)
	}()

	m := &model{sock: sock, w: w, h: h}
	scr := &screen{out: cw}
	scr.resize(w, h)

	msgs := make(chan msg, 64)
	run := func(c cmd) {
		if c != nil {
			go func() { msgs <- c() }()
		}
	}
	go func() {
		buf := make([]byte, 1024)
		var pending []byte
		for {
			n, err := in.Read(buf)
			if err != nil {
				msgs <- quitMsg{}
				return
			}
			var evs []any
			evs, pending = decodeInput(append(pending, buf[:n]...))
			for _, ev := range evs {
				msgs <- ev
			}
		}
	}()

	run(m.fetch())
	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		if err := scr.render(m.render()); err != nil {
			return err
		}
		select {
		case <-ticker.C:
			if w, h, err := term.GetSize(int(out.Fd())); err == nil && (w != m.w || h != m.h) {
				m.w, m.h = w, h
				scr.resize(w, h)
			}
			run(m.fetch())
		case v := <-msgs:
			if _, ok := v.(quitMsg); ok {
				return nil
			}
			if bg, ok := v.(bgMsg); ok {
				setTheme(bg.dark)
				scr.prev = nil // colors changed everywhere: repaint
				continue
			}
			run(m.update(v))
		}
	}
}

func (m *model) fetch() cmd {
	return func() msg {
		resp, err := api.Call(m.sock, api.Request{Cmd: "snapshot"})
		if err != nil {
			return errMsg{err}
		}
		return snapMsg{resp.Snapshot}
	}
}

func (m *model) setStatus(s string) { m.status, m.statusT = s, time.Now() }

// update applies a message; the returned cmd runs asynchronously and its
// result comes back as another message.
func (m *model) update(v msg) cmd {
	switch v := v.(type) {
	case snapMsg:
		m.snap, m.err = v.s, nil
	case errMsg:
		m.err = v.err
	case actionMsg:
		if v.err != nil {
			m.setStatus(sRed.Render("✗ " + v.err.Error()))
		} else {
			m.setStatus(sGreen.Render("✓ " + v.text))
		}
		return m.fetch()
	case key:
		return m.onKey(v)
	}
	return nil
}

// editText applies a key press to a single-line text buffer.
func editText(buf string, k key) string {
	switch {
	case k.name == "backspace":
		if r := []rune(buf); len(r) > 0 {
			return string(r[:len(r)-1])
		}
	case k.text != "":
		return buf + k.text
	}
	return buf
}

func (m *model) onKey(k key) cmd {
	if m.confirm != nil {
		p := m.confirm
		m.confirm = nil
		if k.name == "y" || k.name == "Y" || k.name == "enter" {
			return m.call(p.req)
		}
		m.setStatus(sMuted.Render("已取消"))
		return nil
	}
	if m.adding {
		switch k.name {
		case "enter":
			m.adding = false
			if v := strings.TrimSpace(m.addBuf); v != "" {
				return m.call(api.Request{Cmd: "allow", IP: v})
			}
		case "esc":
			m.adding = false
		default:
			m.addBuf = editText(m.addBuf, k)
		}
		return nil
	}
	if m.editing {
		switch k.name {
		case "enter":
			m.editing = false
		case "esc":
			m.editing, m.filter = false, ""
		default:
			m.filter = editText(m.filter, k)
		}
		m.cursor[m.tab], m.offset[m.tab], m.sel[m.tab] = 0, 0, ""
		return nil
	}
	rows := m.rows()
	switch k.name {
	case "q", "ctrl+c":
		return quit
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % tabCount
	case "shift+tab", "left", "h":
		m.tab = (m.tab + tabCount - 1) % tabCount
	case "1", "2", "3", "4", "5", "6", "7":
		m.tab = tab(k.name[0] - '1')
	case "up", "k":
		m.move(-1, len(rows))
	case "down", "j":
		m.move(1, len(rows))
	case "pgup":
		m.move(-m.pageSize(), len(rows))
	case "pgdown":
		m.move(m.pageSize(), len(rows))
	case "home", "g":
		m.setCursor(0, len(rows))
	case "end", "G":
		m.setCursor(len(rows)-1, len(rows))
	case "/":
		m.editing = true
	case "esc":
		m.filter = ""
	case "s":
		if m.tab == tabAttackers {
			m.sortBy = (m.sortBy + 1) % 3
			m.setStatus("排序: " + [...]string{"失败次数", "最后出现", "封禁次数"}[m.sortBy])
		}
	case "r":
		return m.fetch()
	case "a":
		if m.tab == tabWhitelist {
			m.adding, m.addBuf = true, ""
		}
	case "d", "w", "u", "b", "B":
		if len(rows) == 0 || rows[m.cursor[m.tab]].ip == "" {
			return nil
		}
		r := rows[m.cursor[m.tab]]
		if m.tab == tabWhitelist {
			if k.name == "d" {
				m.confirm = &pending{fmt.Sprintf("从白名单移除 %s ? (y/N)", r.ip), api.Request{Cmd: "disallow", IP: r.ip}}
			}
			return nil
		}
		if k.name == "d" {
			return nil
		}
		if k.name == "w" {
			if r.whitelisted {
				m.setStatus(sMuted.Render(r.ip + " 已在白名单中"))
				return nil
			}
			m.confirm = &pending{fmt.Sprintf("把 %s 加入白名单（永不封禁）? (y/N)", r.ip), api.Request{Cmd: "allow", IP: r.ip}}
			return nil
		}
		if k.name == "u" {
			if !r.banned {
				m.setStatus(sMuted.Render(r.ip + " 当前未被封禁"))
				return nil
			}
			m.confirm = &pending{fmt.Sprintf("解封 %s ? (y/N)", r.ip), api.Request{Cmd: "unban", IP: r.ip}}
		} else if k.name == "B" {
			m.confirm = &pending{fmt.Sprintf("永久封禁 %s ? (y/N)", r.ip), api.Request{Cmd: "ban", IP: r.ip, Duration: "perm"}}
		} else {
			m.confirm = &pending{fmt.Sprintf("封禁 %s (按递增时长)? (y/N)", r.ip), api.Request{Cmd: "ban", IP: r.ip}}
		}
	}
	return nil
}

func (m *model) call(req api.Request) cmd {
	sock := m.sock
	return func() msg {
		resp, err := api.Call(sock, req)
		text := req.Cmd + " " + req.IP + " 完成"
		if err == nil && resp.Message != "" {
			text = resp.Message
		}
		return actionMsg{text: text, err: err}
	}
}

func (m *model) move(d, n int) {
	m.setCursor(m.cursor[m.tab]+d, n)
}

// setCursor moves the cursor and forgets the pinned row so View re-pins the new one.
func (m *model) setCursor(c, n int) {
	m.cursor[m.tab] = max(min(c, n-1), 0)
	m.sel[m.tab] = ""
}

func (r row) id() string {
	if r.key != "" {
		return r.key
	}
	return r.ip
}

// ---- data

func (m *model) columns() []col {
	switch m.tab {
	case tabBanned:
		return []col{{"IP", 40, false}, {"失败", 8, true}, {"封禁#", 6, true}, {"剩余", 10, true}, {"解封时间", 16, false}, {"最后用户", 14, false}, {"最后原因", 0, false}}
	case tabPermanent:
		return []col{{"IP", 40, false}, {"失败", 8, true}, {"封禁#", 6, true}, {"封禁时间", 16, false}, {"最后出现", 10, true}, {"最后用户", 14, false}, {"原因", 0, false}}
	case tabAttackers:
		return []col{{"IP", 40, false}, {"失败", 8, true}, {"成功", 6, true}, {"封禁#", 6, true}, {"状态", 10, false}, {"最后出现", 10, true}, {"常试用户", 0, false}}
	case tabEvents:
		return []col{{"时间", 19, false}, {"类型", 6, false}, {"IP", 40, false}, {"用户", 16, false}, {"密码", 18, false}, {"原因", 0, false}}
	case tabPasswords:
		return []col{{"#", 5, true}, {"密码", 32, false}, {"尝试次数", 10, true}, {"占比", 8, true}, {"", 0, false}}
	case tabWhitelist:
		return []col{{"IP / 网段", 44, false}, {"覆盖的已记录 IP", 16, true}, {"备注", 0, false}}
	default:
		return []col{{"#", 5, true}, {"用户名", 24, false}, {"尝试次数", 10, true}, {"占比", 8, true}, {"", 0, false}}
	}
}

func (m *model) rows() []row {
	if m.snap == nil {
		return nil
	}
	s := m.snap
	now := s.Now
	var out []row
	switch m.tab {
	case tabBanned:
		recs := filterRecs(s.Records, func(r *guard.IPRecord) bool { return r.Banned(now) })
		sort.Slice(recs, func(i, j int) bool {
			if !recs[i].BannedAt.Equal(recs[j].BannedAt) {
				return recs[i].BannedAt.After(recs[j].BannedAt)
			}
			return recs[i].IP < recs[j].IP
		})
		for _, r := range recs {
			left, until, style := countdown(r.BannedUntil.Sub(now)), r.BannedUntil.Local().Format("01-02 15:04:05"), lipgloss.NewStyle()
			if r.Permanent {
				left, until, style = "永久", "永不", sRed
			}
			out = append(out, row{ip: r.IP, banned: true, style: style, cells: []string{
				r.IP, num(r.Failures), fmt.Sprint(r.BanCount), left, until, r.LastUser, banReason(r)}})
		}
	case tabPermanent:
		recs := filterRecs(s.Records, func(r *guard.IPRecord) bool { return r.Permanent })
		sort.Slice(recs, func(i, j int) bool {
			if !recs[i].BannedAt.Equal(recs[j].BannedAt) {
				return recs[i].BannedAt.After(recs[j].BannedAt)
			}
			return recs[i].IP < recs[j].IP
		})
		for _, r := range recs {
			out = append(out, row{ip: r.IP, banned: true, style: sRed, cells: []string{
				r.IP, num(r.Failures), fmt.Sprint(r.BanCount), r.BannedAt.Local().Format("01-02 15:04:05"),
				ago(now.Sub(r.LastSeen)), r.LastUser, banReason(r)}})
		}
	case tabAttackers:
		recs := filterRecs(s.Records, func(r *guard.IPRecord) bool { return r.Failures > 0 || r.Successes > 0 })
		sort.Slice(recs, func(i, j int) bool {
			a, b := recs[i], recs[j]
			// Every ordering ends in a unique key so rows never swap between refreshes.
			switch m.sortBy {
			case 1:
				if !a.LastSeen.Equal(b.LastSeen) {
					return a.LastSeen.After(b.LastSeen)
				}
			case 2:
				if a.BanCount != b.BanCount {
					return a.BanCount > b.BanCount
				}
			}
			if a.Failures != b.Failures {
				return a.Failures > b.Failures
			}
			return a.IP < b.IP
		})
		for _, r := range recs {
			st, style := "监视中", lipgloss.NewStyle()
			if r.Permanent {
				st, style = "永久封禁", sRed
			} else if r.Banned(now) {
				st, style = "已封禁", sRed
			} else if r.Whitelisted {
				st, style = "白名单", sGreen
			}
			out = append(out, row{ip: r.IP, banned: r.Banned(now), whitelisted: r.Whitelisted, style: style, cells: []string{
				r.IP, num(r.Failures), num(r.Successes), fmt.Sprint(r.BanCount), st,
				ago(now.Sub(r.LastSeen)), topUsers(r.Users, 4)}})
		}
	case tabEvents:
		bannedSet := map[string]bool{}
		whiteSet := map[string]bool{}
		for _, r := range s.Records {
			if r.Banned(now) {
				bannedSet[r.IP] = true
			}
			if r.Whitelisted {
				whiteSet[r.IP] = true
			}
		}
		for i := len(s.Recent) - 1; i >= 0; i-- {
			e := s.Recent[i]
			var ty string
			var style lipgloss.Style
			switch e.Type {
			case "fail":
				ty, style = "失败", sYellow
			case "success":
				ty, style = "成功", sGreen
			case "ban":
				ty, style = "封禁", sRed
			case "unban":
				ty, style = "解封", sMuted
			default:
				ty = e.Type
			}
			out = append(out, row{key: e.Time.Format(time.RFC3339Nano) + e.Type + e.IP, ip: e.IP, banned: bannedSet[e.IP], whitelisted: whiteSet[e.IP], style: style, cells: []string{
				e.Time.Local().Format("2006-01-02 15:04:05"), ty, e.IP, e.User, e.Password, e.Reason}})
		}
	case tabUsers:
		out = rankRows(s.Stats.Users)
	case tabPasswords:
		out = rankRows(s.Stats.Passwords)
	case tabWhitelist:
		for _, e := range s.Whitelist {
			n, err := config.ParseCIDROrIP(e)
			covered := 0
			if err == nil {
				for _, r := range s.Records {
					if n.Contains(net.ParseIP(r.IP)) {
						covered++
					}
				}
			}
			note := ""
			if e == "127.0.0.0/8" || e == "::1" {
				note = "本机回环（默认）"
			}
			out = append(out, row{ip: e, style: sGreen, cells: []string{e, num(int64(covered)), note}})
		}
	}
	if m.filter != "" {
		f := strings.ToLower(m.filter)
		kept := out[:0]
		for _, r := range out {
			if strings.Contains(strings.ToLower(strings.Join(r.cells, " ")), f) {
				kept = append(kept, r)
			}
		}
		out = kept
	}
	return out
}

// rankRows turns a name → count map into ranked rows with a share bar.
func rankRows(m map[string]int64) []row {
	type kv struct {
		k string
		v int64
	}
	var list []kv
	var total int64
	for k, v := range m {
		list = append(list, kv{k, v})
		total += v
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	var top int64 = 1
	if len(list) > 0 {
		top = list[0].v
	}
	var out []row
	for i, e := range list {
		pct := float64(e.v) * 100 / float64(max(total, 1))
		bar := strings.Repeat("█", int(float64(e.v)*30/float64(top)))
		out = append(out, row{key: e.k, cells: []string{fmt.Sprint(i + 1), e.k, num(e.v), fmt.Sprintf("%.1f%%", pct), sMuted.Render(bar)}})
	}
	return out
}

func banReason(r *guard.IPRecord) string {
	if r.Manual {
		return "手动封禁"
	}
	return r.LastReason
}

func filterRecs(in []*guard.IPRecord, keep func(*guard.IPRecord) bool) []*guard.IPRecord {
	var out []*guard.IPRecord
	for _, r := range in {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func topUsers(u map[string]int64, n int) string {
	type kv struct {
		k string
		v int64
	}
	var l []kv
	for k, v := range u {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i := 0; i < len(l) && i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s(%d)", l[i].k, l[i].v))
	}
	return strings.Join(parts, " ")
}

// ---- view

const numCards = 9

// cardRows is how many rows of stat cards fit the terminal width (cards need ~16 columns).
func (m *model) cardRows() int {
	perRow := min(max(m.w/16, 1), numCards)
	return (numCards + perRow - 1) / perRow
}

func (m *model) pageSize() int {
	// header(1) + cards(4 per row) + spark(1) + blank(1) + tabs(1) + table head(1) + footer(1)
	return max(m.h-6-4*m.cardRows(), 3)
}

func (m *model) render() string {
	if m.w == 0 {
		return "加载中…"
	}
	if m.snap == nil {
		if m.err != nil {
			return "\n  " + sRed.Render("无法连接守护进程: "+m.err.Error()) + "\n\n  " + sMuted.Render("q 退出")
		}
		return "\n  正在连接 sshshield 守护进程…"
	}
	s := m.snap
	var b strings.Builder

	status := sGreen.Render("● 运行中")
	if m.err != nil {
		status = sRed.Render("● 连接断开")
	}
	left := sTitle.Render(" SSHShield ") + " " + status + sMuted.Render(fmt.Sprintf("  后端 %s · 来源 %s · 规则 %d次/%s → 封 %s起",
		s.Backend, s.Source, s.MaxRetry, s.FindTime, s.BanTime))
	right := sMuted.Render("已运行 " + dur(s.Now.Sub(s.Started)) + " ")
	b.WriteString(spread(left, right, m.w) + "\n")

	today := s.Now.Format("2006-01-02")
	cards := []struct {
		label, value string
		style        lipgloss.Style
	}{
		{"总失败次数", num(s.Stats.TotalFailures), sYellow},
		{"今日失败", num(s.Stats.DailyFailures[today]), sYellow},
		{"当前封禁", num(int64(s.Active)), sRed},
		{"永久封禁", num(int64(s.Perm)), sRed},
		{"累计封禁", num(s.Stats.TotalBans), sRed},
		{"今日封禁", num(s.Stats.DailyBans[today]), sRed},
		{"攻击 IP 数", num(int64(s.UniqueIPs)), sBold},
		{"成功登录", num(s.Stats.TotalSuccesses), sGreen},
		{"捕获密码", num(s.Stats.TotalPasswords), sYellow},
	}
	perRow := (len(cards) + m.cardRows() - 1) / m.cardRows()
	cw := max(m.w/perRow, 12) // lipgloss v2 widths include the border
	for start := 0; start < len(cards); start += perRow {
		var rendered []string
		for _, c := range cards[start:min(start+perRow, len(cards))] {
			rendered = append(rendered, sCard.Width(cw).Render(sMuted.Render(c.label)+"\n"+c.style.Bold(true).Render(c.value)))
		}
		b.WriteString(clip(lipgloss.JoinHorizontal(lipgloss.Top, rendered...), m.w) + "\n")
	}
	b.WriteString(m.spark() + "\n\n")

	rows := m.rows()
	var tabs []string
	for i := tab(0); i < tabCount; i++ {
		label := fmt.Sprintf("%d %s", i+1, tabNames[i])
		if i == m.tab {
			label += fmt.Sprintf(" (%d)", len(rows))
			tabs = append(tabs, sTabOn.Render(label))
		} else {
			tabs = append(tabs, sTabOff.Render(label))
		}
	}
	tabLine := strings.Join(tabs, " ")
	if m.filter != "" || m.editing {
		cur := ""
		if m.editing {
			cur = "▏"
		}
		tabLine += "   " + sAccent("过滤: ") + m.filter + cur
	}
	b.WriteString(tabLine + "\n")

	cols := m.columns()
	widths := m.widths(cols)
	b.WriteString(sHead.Render(fmtRow(headers(cols), cols, widths)) + "\n")

	page := m.pageSize()
	if want := m.sel[m.tab]; want != "" {
		for i, r := range rows {
			if r.id() == want {
				m.cursor[m.tab] = i
				break
			}
		}
	}
	cur := min(m.cursor[m.tab], max(len(rows)-1, 0))
	m.cursor[m.tab] = cur
	if len(rows) > 0 {
		m.sel[m.tab] = rows[cur].id()
	}
	off := m.offset[m.tab]
	if cur < off {
		off = cur
	}
	if cur >= off+page {
		off = cur - page + 1
	}
	m.offset[m.tab] = off
	if len(rows) == 0 {
		b.WriteString(sMuted.Render("  （暂无数据）") + "\n")
	}
	for i := off; i < len(rows) && i < off+page; i++ {
		line := fmtRow(rows[i].cells, cols, widths)
		if i == cur {
			// One style pass: nesting renders would reset the background mid-line.
			line = rows[i].style.Background(cSelBg).Width(m.w - 1).Render(line)
		} else {
			line = rows[i].style.Render(line)
		}
		b.WriteString(line + "\n")
	}
	for i := len(rows) - off; i < page; i++ {
		b.WriteString("\n")
	}

	var foot string
	switch {
	case m.confirm != nil:
		foot = sYellow.Bold(true).Render(m.confirm.prompt)
	case m.adding:
		foot = sYellow.Bold(true).Render("添加白名单 IP 或网段: ") + m.addBuf + "▏" + sMuted.Render("   Enter 确认  Esc 取消")
	case m.editing:
		foot = sMuted.Render("输入过滤文字  Enter 确认  Esc 清除")
	default:
		help := "↑↓ 移动  ←→/Tab/1-7 切换  u 解封  b 封禁  B 永久封禁  w 加白  / 过滤"
		switch m.tab {
		case tabAttackers:
			help += "  s 排序"
		case tabWhitelist:
			help = "↑↓ 移动  ←→/Tab/1-7 切换  a 添加  d 删除  / 过滤"
		}
		help += "  r 刷新  q 退出"
		foot = sMuted.Render(help)
		if m.status != "" && time.Since(m.statusT) < 5*time.Second {
			foot = spread(foot, m.status, m.w)
		}
	}
	b.WriteString(foot)
	return fit(b.String(), m.w, m.h)
}

// fit clips every line to the terminal width and the frame to its height.
// A line that wraps or a frame taller than the screen makes the terminal
// scroll, and the renderer then repaints everything on each refresh (flicker).
func fit(s string, w, h int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, l := range lines {
		if ansi.StringWidth(l) > w {
			lines[i] = ansi.Truncate(l, w, "")
		}
	}
	return strings.Join(lines, "\n")
}

func sAccent(s string) string { return lipgloss.NewStyle().Foreground(cAccent).Render(s) }

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// spark renders the last 14 days of failures as a sparkline.
func (m *model) spark() string {
	const days = 14
	now := m.snap.Now
	vals := make([]int64, days)
	var peak int64
	peakDay := ""
	var sum int64
	for i := 0; i < days; i++ {
		d := now.AddDate(0, 0, i-days+1).Format("2006-01-02")
		vals[i] = m.snap.Stats.DailyFailures[d]
		sum += vals[i]
		if vals[i] > peak {
			peak, peakDay = vals[i], d[5:]
		}
	}
	var sb strings.Builder
	for _, v := range vals {
		if v == 0 {
			sb.WriteRune(' ')
			continue
		}
		idx := int(float64(v) / float64(peak) * float64(len(sparkChars)-1))
		sb.WriteRune(sparkChars[idx])
	}
	line := sMuted.Render(" 近14天失败 ") + sYellow.Render("["+sb.String()+"]")
	if peak > 0 {
		line += sMuted.Render(fmt.Sprintf("  合计 %s · 峰值 %s (%s) · 日均 %s", num(sum), num(peak), peakDay, num(sum/days)))
	}
	return clip(line, m.w)
}

func (m *model) widths(cols []col) []int {
	w := make([]int, len(cols))
	used := 0
	flex := -1
	for i, c := range cols {
		w[i] = c.width
		// IPv4 addresses rarely need 40 columns; shrink IP columns on narrow terminals.
		if c.title == "IP" && m.w < 140 {
			w[i] = 22
		}
		if c.width == 0 {
			flex = i
		}
		used += w[i] + 1
	}
	if flex >= 0 {
		// fmtRow adds a leading space; keep the row strictly narrower than the terminal.
		w[flex] = max(m.w-used-2, 8)
	}
	return w
}

func headers(cols []col) []string {
	h := make([]string, len(cols))
	for i, c := range cols {
		h[i] = c.title
	}
	return h
}

func fmtRow(cells []string, cols []col, widths []int) string {
	var b strings.Builder
	b.WriteByte(' ')
	for i, c := range cols {
		v := ""
		if i < len(cells) {
			v = cells[i]
		}
		v = ansi.Truncate(v, widths[i], "…")
		pad := strings.Repeat(" ", max(widths[i]-ansi.StringWidth(v), 0))
		if c.right {
			b.WriteString(pad + v)
		} else {
			b.WriteString(v + pad)
		}
		b.WriteByte(' ')
	}
	return b.String()
}

func spread(left, right string, w int) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return clip(left, w)
	}
	return left + strings.Repeat(" ", gap) + right
}

func clip(s string, w int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, w, "")
	}
	return strings.Join(lines, "\n")
}

func num(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return s
	}
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}

func dur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	day := d / (24 * time.Hour)
	d -= day * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	mi := d / time.Minute
	sec := (d - mi*time.Minute) / time.Second
	switch {
	case day > 0:
		return fmt.Sprintf("%dd%dh", day, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, mi)
	case mi > 0:
		return fmt.Sprintf("%dm%ds", mi, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

// countdown always shows seconds so a ban's remaining time visibly ticks.
func countdown(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	day := d / (24 * time.Hour)
	h := d % (24 * time.Hour) / time.Hour
	mi := d % time.Hour / time.Minute
	sec := d % time.Minute / time.Second
	switch {
	case day > 0:
		return fmt.Sprintf("%dd%02dh%02dm%02ds", day, h, mi, sec)
	case h > 0:
		return fmt.Sprintf("%dh%02dm%02ds", h, mi, sec)
	case mi > 0:
		return fmt.Sprintf("%dm%02ds", mi, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

// ago is deliberately coarse (minute granularity): a per-second value would
// change every row on every refresh and force the whole table to be redrawn.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%dm前", d/time.Minute)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm前", d/time.Hour, d%time.Hour/time.Minute)
	}
	return fmt.Sprintf("%dd前", d/(24*time.Hour))
}
