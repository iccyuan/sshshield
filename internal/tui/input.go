package tui

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// key is one decoded key press. name uses Bubble Tea style names ("up",
// "enter", "shift+tab", "ctrl+c"); for printable input it equals text.
type key struct {
	name string
	text string
}

// bgMsg reports the terminal background from an OSC 11 reply.
type bgMsg struct{ dark bool }

var csiKeys = map[string]string{
	"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end", "Z": "shift+tab",
	"1~": "home", "7~": "home", "4~": "end", "8~": "end", "5~": "pgup", "6~": "pgdown", "3~": "delete",
}

// decodeInput splits raw terminal input into key presses and OSC replies.
// It returns the events and any trailing incomplete sequence to keep.
func decodeInput(buf []byte) (events []any, rest []byte) {
	for len(buf) > 0 {
		c := buf[0]
		switch {
		case c == 0x1b:
			if len(buf) == 1 {
				return append(events, key{name: "esc"}), nil
			}
			switch buf[1] {
			case '[', 'O':
				// CSI / SS3: parameters then a final byte in 0x40..0x7e.
				i := 2
				for i < len(buf) && (buf[i] < 0x40 || buf[i] > 0x7e) {
					i++
				}
				if i >= len(buf) {
					return events, buf
				}
				seq := string(buf[2 : i+1])
				if n, ok := csiKeys[seq]; ok {
					events = append(events, key{name: n})
				} else if strings.HasSuffix(seq, "~") || len(seq) > 1 {
					// Modified keys like "1;5A": map by final byte, ignore modifiers.
					if n, ok := csiKeys[seq[len(seq)-1:]]; ok {
						events = append(events, key{name: n})
					}
				}
				buf = buf[i+1:]
			case ']':
				// OSC reply, terminated by BEL or ST (ESC \).
				end, skip := -1, 0
				for i := 2; i < len(buf); i++ {
					if buf[i] == 0x07 {
						end, skip = i, 1
						break
					}
					if buf[i] == 0x1b && i+1 < len(buf) && buf[i+1] == '\\' {
						end, skip = i, 2
						break
					}
				}
				if end < 0 {
					return events, buf
				}
				if ev, ok := parseOSC11(string(buf[2:end])); ok {
					events = append(events, ev)
				}
				buf = buf[end+skip:]
			default:
				// Alt+key: treat as a plain Esc followed by the key.
				events = append(events, key{name: "esc"})
				buf = buf[1:]
			}
		case c == '\r' || c == '\n':
			events, buf = append(events, key{name: "enter"}), buf[1:]
		case c == '\t':
			events, buf = append(events, key{name: "tab"}), buf[1:]
		case c == 0x7f || c == 0x08:
			events, buf = append(events, key{name: "backspace"}), buf[1:]
		case c == 0x03:
			events, buf = append(events, key{name: "ctrl+c"}), buf[1:]
		case c < 0x20:
			buf = buf[1:] // other control characters are ignored
		default:
			if !utf8.FullRune(buf) {
				return events, buf
			}
			r, n := utf8.DecodeRune(buf)
			s := string(r)
			if r == ' ' {
				events = append(events, key{name: "space", text: s})
			} else {
				events = append(events, key{name: s, text: s})
			}
			buf = buf[n:]
		}
	}
	return events, nil
}

// parseOSC11 parses "11;rgb:RRRR/GGGG/BBBB".
func parseOSC11(s string) (bgMsg, bool) {
	s, ok := strings.CutPrefix(s, "11;rgb:")
	if !ok {
		return bgMsg{}, false
	}
	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		return bgMsg{}, false
	}
	var ch [3]float64
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 32)
		if err != nil || len(p) == 0 {
			return bgMsg{}, false
		}
		ch[i] = float64(v) / float64(uint64(1)<<(4*len(p))-1)
	}
	lum := 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2]
	return bgMsg{dark: lum < 0.5}, true
}
