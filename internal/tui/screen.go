package tui

import (
	"fmt"
	"io"
	"strings"

	uv "github.com/charmbracelet/ultraviolet"
)

// screen is a minimal cell-diffing renderer.
//
// Bubble Tea's renderers rewrite whole lines (v1 always, v2 whenever the line
// holds a wide character such as CJK). Rewriting unchanged text is invisible on
// most terminals, but Termius re-applies its IP-address highlighting after
// every write, so untouched IPs flashed white once per refresh. This renderer
// only writes the cells that actually changed, never uses erase sequences (so
// it cannot split a wide character), and widens each changed span to whole
// characters on both the old and the new frame.
type screen struct {
	out  io.Writer
	w, h int
	prev *uv.Buffer // what is on the terminal; nil forces a full repaint
}

func (s *screen) resize(w, h int) {
	if w != s.w || h != s.h {
		s.w, s.h, s.prev = w, h, nil
	}
}

// render draws frame (lines separated by "\n", may contain SGR styles).
func (s *screen) render(frame string) error {
	if s.w <= 0 || s.h <= 0 {
		return nil
	}
	next := uv.NewScreenBuffer(s.w, s.h) // wcwidth: CJK is two columns, as in Termius/xterm
	uv.NewStyledString(frame).Draw(next, next.Bounds())

	var b strings.Builder
	full := s.prev == nil
	if full {
		b.WriteString("\x1b[m\x1b[H\x1b[2J")
	}
	for y := 0; y < s.h; y++ {
		var old uv.Line
		if !full {
			old = s.prev.Line(y)
		}
		writeSpan(&b, old, next.Line(y), y)
	}
	s.prev = next.Buffer
	if b.Len() == 0 {
		return nil // nothing changed: write nothing at all
	}
	// Synchronized update (DEC 2026) so supporting terminals paint the frame at once.
	_, err := io.WriteString(s.out, "\x1b[?2026h"+b.String()+"\x1b[m\x1b[?2026l")
	return err
}

func cellAt(l uv.Line, x int) *uv.Cell {
	if x < 0 || x >= len(l) {
		return nil
	}
	return &l[x]
}

// writeSpan emits the smallest run of whole characters covering every column
// where old and cur differ. A nil old line means everything differs.
func writeSpan(b *strings.Builder, old, cur uv.Line, y int) {
	w := len(cur)
	differs := func(x int) bool {
		o := cellAt(old, x)
		return o == nil || !o.Equal(cellAt(cur, x))
	}
	x0, x1 := -1, -1
	for x := 0; x < w; x++ {
		if differs(x) {
			if x0 < 0 {
				x0 = x
			}
			x1 = x
		}
	}
	if x0 < 0 {
		return
	}
	// Grow the span until neither frame has a wide character crossing its edges.
	for changed := true; changed; {
		changed = false
		for _, l := range []uv.Line{old, cur} {
			for x0 > 0 {
				c := cellAt(l, x0)
				if c == nil || c.Width != 0 {
					break
				}
				x0-- // continuation column: step back to the character's head
				changed = true
			}
			for x := x0; x <= x1; x++ {
				if c := cellAt(l, x); c != nil && c.Width > 1 && x+c.Width-1 > x1 {
					x1 = min(x+c.Width-1, w-1)
					changed = true
				}
			}
			for x1+1 < w {
				c := cellAt(l, x1+1)
				if c == nil || c.Width != 0 {
					break
				}
				x1++ // the span ends on a wide head; include its continuation
				changed = true
			}
		}
	}

	fmt.Fprintf(b, "\x1b[%d;%dH\x1b[m", y+1, x0+1)
	var pen uv.Style
	for x := x0; x <= x1; x++ {
		c := cellAt(cur, x)
		if c.Width == 0 {
			continue // continuation of the previous wide character
		}
		if !c.Style.Equal(&pen) {
			b.WriteString(uv.StyleDiff(&pen, &c.Style))
			pen = c.Style
		}
		if c.Content == "" {
			b.WriteByte(' ')
		} else {
			b.WriteString(c.Content)
		}
	}
	if !pen.IsZero() {
		b.WriteString("\x1b[m")
	}
}
