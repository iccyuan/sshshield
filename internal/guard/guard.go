// Package guard counts failures per IP, decides bans and persists all statistics.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/iccyuan/sshshield/internal/config"
	"github.com/iccyuan/sshshield/internal/firewall"
	"github.com/iccyuan/sshshield/internal/parser"
)

const (
	maxRecent       = 500
	maxUsersPerIP   = 30
	maxGlobalUsers  = 500
	keepDays        = 60
	softFailGrace   = 30 * time.Second
	eventLogMaxSize = 20 << 20

	maxPasswordsPerIP  = 30
	maxGlobalPasswords = 2000
	maxPasswordLen     = 64
	maxPendingPerIP    = 10
	// A captured password is kept only if sshd logs a failure for it within this window.
	passwordMatchWindow = 30 * time.Second
)

// Permanent as a ban duration means the ban never expires.
const Permanent time.Duration = -1

type IPRecord struct {
	IP          string           `json:"ip"`
	Failures    int64            `json:"failures"`
	Successes   int64            `json:"successes"`
	BanCount    int              `json:"ban_count"`
	FirstSeen   time.Time        `json:"first_seen"`
	LastSeen    time.Time        `json:"last_seen"`
	BannedAt    time.Time        `json:"banned_at,omitzero"`
	BannedUntil time.Time        `json:"banned_until,omitzero"`
	Manual      bool             `json:"manual,omitempty"`
	Permanent   bool             `json:"permanent,omitempty"`   // BannedUntil is zero while set
	Whitelisted bool             `json:"whitelisted,omitempty"` // computed per snapshot from ignore_ip
	LastUser    string           `json:"last_user,omitempty"`
	LastReason  string           `json:"last_reason,omitempty"`
	Users       map[string]int64 `json:"users,omitempty"`
	Passwords   map[string]int64 `json:"passwords,omitempty"`
	// Recent failure timestamps inside find_time, used for the ban decision.
	Window []time.Time `json:"window,omitempty"`
	// Last hard failure, used to avoid double counting the trailing preauth disconnect.
	lastHardFail time.Time
}

func (r *IPRecord) Banned(now time.Time) bool { return r.Permanent || now.Before(r.BannedUntil) }

type Event struct {
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
	User     string    `json:"user,omitempty"`
	Password string    `json:"password,omitempty"`
	Type     string    `json:"type"` // fail | success | ban | unban
	Reason   string    `json:"reason,omitempty"`
}

type Stats struct {
	TotalFailures  int64            `json:"total_failures"`
	TotalSuccesses int64            `json:"total_successes"`
	TotalBans      int64            `json:"total_bans"`
	FirstStart     time.Time        `json:"first_start"`
	DailyFailures  map[string]int64 `json:"daily_failures"`
	DailyBans      map[string]int64 `json:"daily_bans"`
	Users          map[string]int64 `json:"users"`
	TotalPasswords int64            `json:"total_passwords"` // failed attempts whose password was captured
	Passwords      map[string]int64 `json:"passwords"`
}

type state struct {
	Stats   Stats                `json:"stats"`
	Records map[string]*IPRecord `json:"records"`
	Recent  []Event              `json:"recent"`
}

type Guard struct {
	cfg     *config.Config
	fw      firewall.Backend
	source  string
	cfgPath string // where whitelist edits are saved; empty = in-memory only
	started time.Time

	mu      sync.Mutex
	st      state
	dirty   bool
	evLog   *os.File
	evLogSz int64
	// Passwords from the PAM hook waiting for sshd to log whether they failed.
	pending map[string][]pendingPassword
}

type pendingPassword struct {
	user, password string
	at             time.Time
}

func New(cfg *config.Config, cfgPath string, fw firewall.Backend, source string) (*Guard, error) {
	g := &Guard{cfg: cfg, cfgPath: cfgPath, fw: fw, source: source, started: time.Now(), pending: map[string][]pendingPassword{}}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := g.load(); err != nil {
		return nil, err
	}
	if g.st.Stats.FirstStart.IsZero() {
		g.st.Stats.FirstStart = g.started
	}
	f, err := os.OpenFile(filepath.Join(cfg.StateDir, "events.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	g.evLog = f
	if st, err := f.Stat(); err == nil {
		g.evLogSz = st.Size()
	}
	return g, nil
}

func (g *Guard) statePath() string { return filepath.Join(g.cfg.StateDir, "state.json") }

func (g *Guard) load() error {
	g.st = state{Records: map[string]*IPRecord{}}
	b, err := os.ReadFile(g.statePath())
	if errors.Is(err, os.ErrNotExist) {
		g.fillMaps()
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &g.st); err != nil {
		// Keep the broken file for inspection instead of silently losing history.
		bak := g.statePath() + ".corrupt"
		_ = os.Rename(g.statePath(), bak)
		log.Printf("state file unreadable (%v), moved to %s and starting fresh", err, bak)
		g.st = state{Records: map[string]*IPRecord{}}
	}
	g.fillMaps()
	return nil
}

func (g *Guard) fillMaps() {
	s := &g.st.Stats
	if s.DailyFailures == nil {
		s.DailyFailures = map[string]int64{}
	}
	if s.DailyBans == nil {
		s.DailyBans = map[string]int64{}
	}
	if s.Users == nil {
		s.Users = map[string]int64{}
	}
	if s.Passwords == nil {
		s.Passwords = map[string]int64{}
	}
	if g.st.Records == nil {
		g.st.Records = map[string]*IPRecord{}
	}
}

// Save writes state atomically if anything changed.
func (g *Guard) Save() error {
	g.mu.Lock()
	if !g.dirty {
		g.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(&g.st)
	g.dirty = false
	g.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := g.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.statePath())
}

// RestoreBans re-applies bans that are still active after a restart.
func (g *Guard) RestoreBans() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	n := 0
	for _, r := range g.st.Records {
		if !r.Banned(now) {
			continue
		}
		d := Permanent
		if !r.Permanent {
			d = r.BannedUntil.Sub(now)
		}
		if err := g.fw.Ban(net.ParseIP(r.IP), d); err != nil {
			log.Printf("restore ban %s: %v", r.IP, err)
			continue
		}
		n++
	}
	if n > 0 {
		log.Printf("restored %d active bans", n)
	}
}

// Heal rebuilds the firewall rules and re-applies active bans if something
// external (firewalld reload, iptables-restore, nft flush) removed them.
func (g *Guard) Heal() {
	if err := g.fw.Check(); err == nil {
		return
	}
	log.Printf("firewall rules missing, rebuilding")
	if err := g.fw.Setup(); err != nil {
		log.Printf("firewall rebuild failed: %v", err)
		return
	}
	g.RestoreBans()
}

func day(t time.Time) string { return t.Format("2006-01-02") }

func (g *Guard) record(ip string, now time.Time) *IPRecord {
	r := g.st.Records[ip]
	if r == nil {
		r = &IPRecord{IP: ip, FirstSeen: now}
		g.st.Records[ip] = r
	}
	r.LastSeen = now
	return r
}

// Handle processes one parsed log event.
func (g *Guard) Handle(ev parser.Event) {
	now := time.Now()
	ip := ev.IP.String()
	g.mu.Lock()
	defer g.mu.Unlock()
	// Whitelisted IPs are still counted; they are only exempt from banning.
	ignored := g.cfg.Ignored(ev.IP)

	r := g.record(ip, now)
	g.dirty = true
	if ev.Kind == parser.Success {
		delete(g.pending, ip) // the password was right: never keep it
		r.Successes++
		g.st.Stats.TotalSuccesses++
		g.addEvent(Event{Time: now, IP: ip, User: ev.User, Type: "success", Reason: ev.Reason})
		return
	}
	if ev.Kind == parser.SoftFail && now.Sub(r.lastHardFail) < softFailGrace {
		return
	}
	if ev.Kind == parser.Fail {
		r.lastHardFail = now
	}

	var password string
	if ev.Kind == parser.Fail && ev.Reason == "bad password" {
		password = g.takePending(ip, ev.User, now)
	}
	r.Failures++
	r.LastReason = ev.Reason
	g.st.Stats.TotalFailures++
	g.st.Stats.DailyFailures[day(now)]++
	if ev.User != "" {
		r.LastUser = ev.User
		if r.Users == nil {
			r.Users = map[string]int64{}
		}
		if _, ok := r.Users[ev.User]; ok || len(r.Users) < maxUsersPerIP {
			r.Users[ev.User]++
		}
		if _, ok := g.st.Stats.Users[ev.User]; ok || len(g.st.Stats.Users) < maxGlobalUsers {
			g.st.Stats.Users[ev.User]++
		}
	}
	if password != "" {
		g.st.Stats.TotalPasswords++
		if r.Passwords == nil {
			r.Passwords = map[string]int64{}
		}
		if _, ok := r.Passwords[password]; ok || len(r.Passwords) < maxPasswordsPerIP {
			r.Passwords[password]++
		}
		if _, ok := g.st.Stats.Passwords[password]; ok || len(g.st.Stats.Passwords) < maxGlobalPasswords {
			g.st.Stats.Passwords[password]++
		}
	}
	g.addEvent(Event{Time: now, IP: ip, User: ev.User, Password: password, Type: "fail", Reason: ev.Reason})

	if ignored || r.Banned(now) {
		return // whitelisted, or a straggling log line from before the ban took effect
	}
	cut := now.Add(-g.cfg.FindTime.D())
	w := r.Window[:0]
	for _, t := range r.Window {
		if t.After(cut) {
			w = append(w, t)
		}
	}
	r.Window = append(w, now)
	if len(r.Window) >= g.cfg.MaxRetry {
		g.ban(r, g.banDuration(r.BanCount), false, fmt.Sprintf("%d failures in %s", len(r.Window), g.cfg.FindTime.D()))
	}
}

func (g *Guard) banDuration(prior int) time.Duration {
	if g.cfg.PermAfter > 0 && prior >= g.cfg.PermAfter {
		return Permanent
	}
	d := float64(g.cfg.BanTime.D()) * math.Pow(g.cfg.BanTimeFactor, float64(prior))
	if d > float64(g.cfg.MaxBanTime.D()) || math.IsInf(d, 0) {
		return g.cfg.MaxBanTime.D()
	}
	return time.Duration(d)
}

func durText(d time.Duration) string {
	if d < 0 {
		return "永久"
	}
	return d.Round(time.Second).String()
}

// ban must be called with g.mu held; d < 0 bans permanently.
func (g *Guard) ban(r *IPRecord, d time.Duration, manual bool, reason string) {
	now := time.Now()
	if err := g.fw.Ban(net.ParseIP(r.IP), d); err != nil {
		log.Printf("ban %s failed: %v", r.IP, err)
		return
	}
	r.BanCount++
	r.BannedAt = now
	r.Permanent = d < 0
	r.BannedUntil = time.Time{}
	if !r.Permanent {
		r.BannedUntil = now.Add(d)
	}
	r.Manual = manual
	r.Window = nil
	g.st.Stats.TotalBans++
	g.st.Stats.DailyBans[day(now)]++
	g.dirty = true
	log.Printf("BAN %s for %s (%s, ban #%d)", r.IP, durText(d), reason, r.BanCount)
	g.addEvent(Event{Time: now, IP: r.IP, Type: "ban", Reason: fmt.Sprintf("%s, %s", reason, durText(d))})
}

func (g *Guard) unban(r *IPRecord, reason string) error {
	err := g.fw.Unban(net.ParseIP(r.IP))
	r.BannedUntil = time.Time{}
	r.Permanent = false
	r.Manual = false
	g.dirty = true
	log.Printf("UNBAN %s (%s)", r.IP, reason)
	g.addEvent(Event{Time: time.Now(), IP: r.IP, Type: "unban", Reason: reason})
	return err
}

// Tick expires bans and prunes old data; call periodically.
func (g *Guard) Tick() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for ip, r := range g.st.Records {
		if !r.Permanent && !r.BannedUntil.IsZero() && !r.Banned(now) {
			// nftables already dropped the element via its timeout; ignore that error.
			_ = g.unban(r, "expired")
		}
		idle := now.Sub(r.LastSeen)
		if !r.Banned(now) && g.cfg.ForgetAfter > 0 && idle > g.cfg.ForgetAfter.D() {
			delete(g.st.Records, ip)
			g.dirty = true
		}
	}
	for ip, p := range g.pending {
		if now.Sub(p[len(p)-1].at) > passwordMatchWindow {
			delete(g.pending, ip)
		}
	}
	cut := day(now.AddDate(0, 0, -keepDays))
	for _, m := range []map[string]int64{g.st.Stats.DailyFailures, g.st.Stats.DailyBans} {
		for d := range m {
			if d < cut {
				delete(m, d)
				g.dirty = true
			}
		}
	}
}

// addEvent must be called with g.mu held.
func (g *Guard) addEvent(e Event) {
	g.st.Recent = append(g.st.Recent, e)
	if len(g.st.Recent) > maxRecent {
		g.st.Recent = append([]Event(nil), g.st.Recent[len(g.st.Recent)-maxRecent:]...)
	}
	b, _ := json.Marshal(e)
	b = append(b, '\n')
	if g.evLogSz+int64(len(b)) > eventLogMaxSize {
		p := g.evLog.Name()
		g.evLog.Close()
		_ = os.Rename(p, p+".1")
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			g.evLog = f
		}
		g.evLogSz = 0
	}
	n, _ := g.evLog.Write(b)
	g.evLogSz += int64(n)
}

// PasswordAttempt holds a password reported by the PAM hook until sshd logs
// the outcome: it is recorded on "Failed password" and dropped on success.
func (g *Guard) PasswordAttempt(ipStr, user, password string) error {
	ip := parser.NormalizeIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	if IsSSHDFakePassword(password) {
		return nil
	}
	password = cleanPassword(password)
	if password == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.Ignored(ip) {
		return nil // never store what our own admins type
	}
	k := ip.String()
	p := append(g.pending[k], pendingPassword{user: user, password: password, at: time.Now()})
	if len(p) > maxPendingPerIP {
		p = p[len(p)-maxPendingPerIP:]
	}
	g.pending[k] = p
	return nil
}

// takePending pops the oldest fresh password for ip (preferring the same user).
// Must be called with g.mu held.
func (g *Guard) takePending(ip, user string, now time.Time) string {
	p := g.pending[ip]
	pick := -1
	for i, e := range p {
		if now.Sub(e.at) > passwordMatchWindow {
			continue
		}
		if e.user == user {
			pick = i
			break
		}
		if pick < 0 {
			pick = i
		}
	}
	if pick < 0 {
		return ""
	}
	pw := p[pick].password
	g.pending[ip] = append(p[:pick:pick], p[pick+1:]...)
	if len(g.pending[ip]) == 0 {
		delete(g.pending, ip)
	}
	return pw
}

// sshdFakeJunk is what sshd repeats in place of the typed password.
const sshdFakeJunk = "\b\n\r\177INCORRECT"

// IsSSHDFakePassword reports whether pw is sshd's stand-in for a password it
// refuses to give PAM (invalid users, and root when PermitRootLogin is not
// "yes"): the junk string cycled to the typed password's length, so only the
// length of the real password survives.
func IsSSHDFakePassword(pw string) bool {
	if pw == "" {
		return false
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] != sshdFakeJunk[i%len(sshdFakeJunk)] {
			return false
		}
	}
	return true
}

// cleanPassword escapes control characters so a password can never inject
// terminal escape sequences into the TUI, and caps its length.
func cleanPassword(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxPasswordLen {
			b.WriteString("…")
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\x%02x", r)
		}
		n++
	}
	return b.String()
}

// ManualBan bans ip for d (0 = the escalating default, Permanent = forever).
func (g *Guard) ManualBan(ipStr string, d time.Duration) error {
	ip := parser.NormalizeIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.Ignored(ip) {
		return fmt.Errorf("%s 在白名单中", ip)
	}
	r := g.record(ip.String(), time.Now())
	if d == 0 {
		d = g.banDuration(r.BanCount)
	}
	g.ban(r, d, true, "manual")
	if !r.Banned(time.Now()) {
		return fmt.Errorf("firewall refused ban, see daemon log")
	}
	return nil
}

func (g *Guard) ManualUnban(ipStr string) error {
	ip := parser.NormalizeIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.st.Records[ip.String()]
	if r == nil || !r.Banned(time.Now()) {
		return fmt.Errorf("%s is not banned", ip)
	}
	if err := g.unban(r, "manual"); err != nil {
		return err
	}
	r.Window = nil
	return nil
}

// ---- whitelist (ignore_ip), editable at runtime and written back to the config file

// WhitelistAdd adds an IP or CIDR and lifts any active bans it covers.
func (g *Guard) WhitelistAdd(entry string) (string, error) {
	n, err := config.ParseCIDROrIP(entry)
	if err != nil {
		return "", fmt.Errorf("%q 不是有效的 IP 或网段", entry)
	}
	norm := config.FormatNet(n)
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.cfg.IgnoreIP {
		if en, err := config.ParseCIDROrIP(e); err == nil && config.FormatNet(en) == norm {
			return "", fmt.Errorf("%s 已在白名单中", norm)
		}
	}
	old := g.cfg.IgnoreIP
	g.cfg.IgnoreIP = append(append([]string(nil), old...), norm)
	if err := g.commitConfig(old); err != nil {
		return "", err
	}
	now := time.Now()
	lifted := 0
	for _, r := range g.st.Records {
		if r.Banned(now) && n.Contains(net.ParseIP(r.IP)) {
			_ = g.unban(r, "whitelisted")
			r.Window = nil
			lifted++
		}
	}
	msg := "已加入白名单 " + norm
	if lifted > 0 {
		msg += fmt.Sprintf("，并解封 %d 个 IP", lifted)
	}
	log.Printf("WHITELIST add %s (lifted %d bans)", norm, lifted)
	return msg, nil
}

func (g *Guard) WhitelistDel(entry string) (string, error) {
	n, err := config.ParseCIDROrIP(entry)
	if err != nil {
		return "", fmt.Errorf("%q 不是有效的 IP 或网段", entry)
	}
	norm := config.FormatNet(n)
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.cfg.IgnoreIP
	var kept []string
	for _, e := range old {
		if en, err := config.ParseCIDROrIP(e); err == nil && config.FormatNet(en) == norm {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == len(old) {
		return "", fmt.Errorf("%s 不在白名单中", norm)
	}
	g.cfg.IgnoreIP = kept
	if err := g.commitConfig(old); err != nil {
		return "", err
	}
	log.Printf("WHITELIST del %s", norm)
	return "已从白名单移除 " + norm, nil
}

// commitConfig validates and persists g.cfg, restoring old ignore_ip on failure.
// Must be called with g.mu held.
func (g *Guard) commitConfig(old []string) error {
	if err := g.cfg.Validate(); err != nil {
		g.cfg.IgnoreIP = old
		_ = g.cfg.Validate()
		return err
	}
	if g.cfgPath == "" {
		return nil
	}
	if err := g.cfg.Save(g.cfgPath); err != nil {
		g.cfg.IgnoreIP = old
		_ = g.cfg.Validate()
		return fmt.Errorf("写入配置失败: %w", err)
	}
	return nil
}

// ---- snapshot for the API / TUI

type Snapshot struct {
	Now       time.Time   `json:"now"`
	Started   time.Time   `json:"started"`
	Backend   string      `json:"backend"`
	Source    string      `json:"source"`
	MaxRetry  int         `json:"max_retry"`
	FindTime  string      `json:"find_time"`
	BanTime   string      `json:"ban_time"`
	Stats     Stats       `json:"stats"`
	Active    int         `json:"active_bans"` // temporary bans only; permanent ones are counted in Perm
	Perm      int         `json:"permanent_bans"`
	UniqueIPs int         `json:"unique_ips"`
	Whitelist []string    `json:"whitelist"`
	Records   []*IPRecord `json:"records"`
	Recent    []Event     `json:"recent"`
}

const maxSnapshotRecords = 3000

func (g *Guard) Snapshot() *Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	s := &Snapshot{
		Now: now, Started: g.started, Backend: g.fw.Name(), Source: g.source,
		MaxRetry: g.cfg.MaxRetry, FindTime: g.cfg.FindTime.D().String(), BanTime: g.cfg.BanTime.D().String(),
		UniqueIPs: len(g.st.Records),
		Whitelist: append([]string(nil), g.cfg.IgnoreIP...),
	}
	b, _ := json.Marshal(g.st.Stats)
	_ = json.Unmarshal(b, &s.Stats)
	s.Records = make([]*IPRecord, 0, len(g.st.Records))
	for _, r := range g.st.Records {
		if r.Permanent {
			s.Perm++
		} else if r.Banned(now) {
			s.Active++
		}
		c := *r
		c.Window = nil
		c.Whitelisted = g.cfg.Ignored(net.ParseIP(r.IP))
		c.Users = make(map[string]int64, len(r.Users))
		for k, v := range r.Users {
			c.Users[k] = v
		}
		c.Passwords = make(map[string]int64, len(r.Passwords))
		for k, v := range r.Passwords {
			c.Passwords[k] = v
		}
		s.Records = append(s.Records, &c)
	}
	// Keep banned IPs plus the heaviest attackers if the list is huge.
	sort.Slice(s.Records, func(i, j int) bool {
		bi, bj := s.Records[i].Banned(now), s.Records[j].Banned(now)
		if bi != bj {
			return bi
		}
		if s.Records[i].Failures != s.Records[j].Failures {
			return s.Records[i].Failures > s.Records[j].Failures
		}
		return s.Records[i].IP < s.Records[j].IP // map order is random; keep output stable
	})
	if len(s.Records) > maxSnapshotRecords {
		s.Records = s.Records[:maxSnapshotRecords]
	}
	s.Recent = append([]Event(nil), g.st.Recent...)
	return s
}

func (g *Guard) Close() {
	_ = g.Save()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.evLog != nil {
		g.evLog.Close()
	}
}
