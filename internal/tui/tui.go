// Package tui is the interactive terminal dashboard.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/iccyuan/sshshield/internal/api"
	"github.com/iccyuan/sshshield/internal/guard"
)

const refreshEvery = 2 * time.Second

var (
	cAccent = lipgloss.AdaptiveColor{Light: "#0969da", Dark: "#58a6ff"}
	cRed    = lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#ff7b72"}
	cGreen  = lipgloss.AdaptiveColor{Light: "#1a7f37", Dark: "#3fb950"}
	cYellow = lipgloss.AdaptiveColor{Light: "#9a6700", Dark: "#d29922"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#6e7781", Dark: "#8b949e"}
	cBorder = lipgloss.AdaptiveColor{Light: "#d0d7de", Dark: "#30363d"}
	cSelBg  = lipgloss.AdaptiveColor{Light: "#ddf4ff", Dark: "#1f2d3d"}

	sTitle  = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sMuted  = lipgloss.NewStyle().Foreground(cMuted)
	sRed    = lipgloss.NewStyle().Foreground(cRed)
	sGreen  = lipgloss.NewStyle().Foreground(cGreen)
	sYellow = lipgloss.NewStyle().Foreground(cYellow)
	sBold   = lipgloss.NewStyle().Bold(true)
	sCard   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(0, 1)
	sTabOn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")).Background(cAccent).Padding(0, 1)
	sTabOff = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 1)
	sHead   = lipgloss.NewStyle().Bold(true).Foreground(cMuted)
	sSel    = lipgloss.NewStyle().Background(cSelBg)
)

type tab int

const (
	tabBanned tab = iota
	tabAttackers
	tabEvents
	tabUsers
	tabCount
)

var tabNames = [...]string{"封禁中", "攻击来源", "最近事件", "用户名排行"}

type col struct {
	title string
	width int // 0 = take the remaining space
	right bool
}

type row struct {
	cells  []string
	ip     string
	banned bool
	style  lipgloss.Style
}

type (
	snapMsg   struct{ s *guard.Snapshot }
	errMsg    struct{ err error }
	actionMsg struct {
		text string
		err  error
	}
	tickMsg struct{}
)

type model struct {
	sock    string
	snap    *guard.Snapshot
	err     error
	w, h    int
	tab     tab
	cursor  [tabCount]int
	offset  [tabCount]int
	sortBy  int // attackers: 0 failures, 1 last seen, 2 bans
	filter  string
	editing bool
	confirm *pending
	status  string
	statusT time.Time
}

type pending struct {
	prompt string
	req    api.Request
}

func Run(sock string) error {
	m := &model{sock: sock}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m *model) fetch() tea.Cmd {
	return func() tea.Msg {
		resp, err := api.Call(m.sock, api.Request{Cmd: "snapshot"})
		if err != nil {
			return errMsg{err}
		}
		return snapMsg{resp.Snapshot}
	}
}

func tick() tea.Cmd {
	return tea.Tick(refreshEvery, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) Init() tea.Cmd { return tea.Batch(m.fetch(), tick()) }

func (m *model) setStatus(s string) { m.status, m.statusT = s, time.Now() }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case snapMsg:
		m.snap, m.err = msg.s, nil
	case errMsg:
		m.err = msg.err
	case tickMsg:
		return m, tea.Batch(m.fetch(), tick())
	case actionMsg:
		if msg.err != nil {
			m.setStatus(sRed.Render("✗ " + msg.err.Error()))
		} else {
			m.setStatus(sGreen.Render("✓ " + msg.text))
		}
		return m, m.fetch()
	case tea.KeyMsg:
		return m, m.key(msg)
	}
	return m, nil
}

func (m *model) key(k tea.KeyMsg) tea.Cmd {
	if m.confirm != nil {
		p := m.confirm
		m.confirm = nil
		if k.String() == "y" || k.String() == "Y" || k.String() == "enter" {
			sock := m.sock
			return func() tea.Msg {
				_, err := api.Call(sock, p.req)
				return actionMsg{text: p.req.Cmd + " " + p.req.IP + " 完成", err: err}
			}
		}
		m.setStatus(sMuted.Render("已取消"))
		return nil
	}
	if m.editing {
		switch k.Type {
		case tea.KeyEnter:
			m.editing = false
		case tea.KeyEsc:
			m.editing, m.filter = false, ""
		case tea.KeyBackspace:
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			m.filter += string(k.Runes)
		}
		m.cursor[m.tab], m.offset[m.tab] = 0, 0
		return nil
	}
	rows := m.rows()
	switch k.String() {
	case "q", "ctrl+c":
		return tea.Quit
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % tabCount
	case "shift+tab", "left", "h":
		m.tab = (m.tab + tabCount - 1) % tabCount
	case "1", "2", "3", "4":
		m.tab = tab(k.String()[0] - '1')
	case "up", "k":
		m.move(-1, len(rows))
	case "down", "j":
		m.move(1, len(rows))
	case "pgup":
		m.move(-m.pageSize(), len(rows))
	case "pgdown":
		m.move(m.pageSize(), len(rows))
	case "home", "g":
		m.cursor[m.tab] = 0
	case "end", "G":
		m.cursor[m.tab] = max(len(rows)-1, 0)
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
	case "u", "b":
		if len(rows) == 0 || rows[m.cursor[m.tab]].ip == "" {
			return nil
		}
		r := rows[m.cursor[m.tab]]
		if k.String() == "u" {
			if !r.banned {
				m.setStatus(sMuted.Render(r.ip + " 当前未被封禁"))
				return nil
			}
			m.confirm = &pending{fmt.Sprintf("解封 %s ? (y/N)", r.ip), api.Request{Cmd: "unban", IP: r.ip}}
		} else {
			m.confirm = &pending{fmt.Sprintf("封禁 %s (按递增时长)? (y/N)", r.ip), api.Request{Cmd: "ban", IP: r.ip}}
		}
	}
	return nil
}

func (m *model) move(d, n int) {
	c := m.cursor[m.tab] + d
	c = min(c, n-1)
	m.cursor[m.tab] = max(c, 0)
}

// ---- data

func (m *model) columns() []col {
	switch m.tab {
	case tabBanned:
		return []col{{"IP", 40, false}, {"失败", 8, true}, {"封禁#", 6, true}, {"剩余", 10, true}, {"解封时间", 16, false}, {"最后用户", 14, false}, {"最后原因", 0, false}}
	case tabAttackers:
		return []col{{"IP", 40, false}, {"失败", 8, true}, {"成功", 6, true}, {"封禁#", 6, true}, {"状态", 10, false}, {"最后出现", 10, true}, {"常试用户", 0, false}}
	case tabEvents:
		return []col{{"时间", 19, false}, {"类型", 6, false}, {"IP", 40, false}, {"用户", 16, false}, {"原因", 0, false}}
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
		sort.Slice(recs, func(i, j int) bool { return recs[i].BannedAt.After(recs[j].BannedAt) })
		for _, r := range recs {
			reason := r.LastReason
			if r.Manual {
				reason = "手动封禁"
			}
			out = append(out, row{ip: r.IP, banned: true, cells: []string{
				r.IP, num(r.Failures), fmt.Sprint(r.BanCount), dur(r.BannedUntil.Sub(now)),
				r.BannedUntil.Local().Format("01-02 15:04:05"), r.LastUser, reason}})
		}
	case tabAttackers:
		recs := filterRecs(s.Records, func(r *guard.IPRecord) bool { return r.Failures > 0 })
		sort.Slice(recs, func(i, j int) bool {
			a, b := recs[i], recs[j]
			switch m.sortBy {
			case 1:
				return a.LastSeen.After(b.LastSeen)
			case 2:
				if a.BanCount != b.BanCount {
					return a.BanCount > b.BanCount
				}
			}
			return a.Failures > b.Failures
		})
		for _, r := range recs {
			st, style := "监视中", lipgloss.NewStyle()
			if r.Banned(now) {
				st, style = "已封禁", sRed
			}
			out = append(out, row{ip: r.IP, banned: r.Banned(now), style: style, cells: []string{
				r.IP, num(r.Failures), num(r.Successes), fmt.Sprint(r.BanCount), st,
				ago(now.Sub(r.LastSeen)), topUsers(r.Users, 4)}})
		}
	case tabEvents:
		bannedSet := map[string]bool{}
		for _, r := range s.Records {
			if r.Banned(now) {
				bannedSet[r.IP] = true
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
			out = append(out, row{ip: e.IP, banned: bannedSet[e.IP], style: style, cells: []string{
				e.Time.Local().Format("2006-01-02 15:04:05"), ty, e.IP, e.User, e.Reason}})
		}
	case tabUsers:
		type kv struct {
			k string
			v int64
		}
		var list []kv
		var total int64
		for k, v := range s.Stats.Users {
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
		for i, e := range list {
			pct := float64(e.v) * 100 / float64(max(total, 1))
			bar := strings.Repeat("█", int(float64(e.v)*30/float64(top)))
			out = append(out, row{cells: []string{fmt.Sprint(i + 1), e.k, num(e.v), fmt.Sprintf("%.1f%%", pct), sMuted.Render(bar)}})
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
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v })
	var parts []string
	for i := 0; i < len(l) && i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s(%d)", l[i].k, l[i].v))
	}
	return strings.Join(parts, " ")
}

// ---- view

const numCards = 7

// cardRows is how many rows of stat cards fit the terminal width (cards need ~16 columns).
func (m *model) cardRows() int {
	perRow := min(max(m.w/16, 1), numCards)
	return (numCards + perRow - 1) / perRow
}

func (m *model) pageSize() int {
	// header(1) + cards(4 per row) + spark(1) + blank(1) + tabs(1) + table head(1) + footer(1)
	return max(m.h-6-4*m.cardRows(), 3)
}

func (m *model) View() string {
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
		{"累计封禁", num(s.Stats.TotalBans), sRed},
		{"今日封禁", num(s.Stats.DailyBans[today]), sRed},
		{"攻击 IP 数", num(int64(s.UniqueIPs)), sBold},
		{"成功登录", num(s.Stats.TotalSuccesses), sGreen},
	}
	perRow := (len(cards) + m.cardRows() - 1) / m.cardRows()
	cw := max(m.w/perRow-2, 10)
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
	cur := min(m.cursor[m.tab], max(len(rows)-1, 0))
	m.cursor[m.tab] = cur
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
			line = sSel.Width(m.w).Render(rows[i].style.Render(line))
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
	case m.editing:
		foot = sMuted.Render("输入过滤文字  Enter 确认  Esc 清除")
	default:
		help := "↑↓ 移动  ←→/Tab/1-4 切换  u 解封  b 封禁  / 过滤"
		if m.tab == tabAttackers {
			help += "  s 排序"
		}
		help += "  r 刷新  q 退出"
		foot = sMuted.Render(help)
		if m.status != "" && time.Since(m.statusT) < 5*time.Second {
			foot = spread(foot, m.status, m.w)
		}
	}
	b.WriteString(foot)
	return b.String()
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
		w[flex] = max(m.w-used-1, 8)
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

func ago(d time.Duration) string {
	if d < 5*time.Second {
		return "刚刚"
	}
	return dur(d) + "前"
}
