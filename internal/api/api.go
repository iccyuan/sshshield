// Package api is the local unix-socket protocol between the daemon and the CLI/TUI.
package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/iccyuan/sshshield/internal/guard"
)

type Request struct {
	Cmd      string `json:"cmd"` // snapshot | ban | unban | allow | disallow
	IP       string `json:"ip,omitempty"`
	Duration string `json:"duration,omitempty"`
}

type Response struct {
	OK       bool            `json:"ok"`
	Message  string          `json:"message,omitempty"`
	Error    string          `json:"error,omitempty"`
	Snapshot *guard.Snapshot `json:"snapshot,omitempty"`
}

// Serve listens on path (root-only) until the listener is closed.
func Serve(path string, g *guard.Guard) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("api accept: %v", err)
				}
				return
			}
			go handle(c, g)
		}
	}()
	return ln, nil
}

func handle(c net.Conn, g *guard.Guard) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		return
	}
	resp := Response{OK: true}
	var err error
	switch req.Cmd {
	case "snapshot":
		resp.Snapshot = g.Snapshot()
	case "ban":
		var d time.Duration
		switch req.Duration {
		case "":
		case "perm", "permanent", "forever", "永久":
			d = guard.Permanent
		default:
			d, err = time.ParseDuration(req.Duration)
			if err == nil && d <= 0 {
				err = fmt.Errorf("时长必须大于 0，永久封禁请用 perm")
			}
		}
		if err == nil {
			err = g.ManualBan(req.IP, d)
		}
	case "unban":
		err = g.ManualUnban(req.IP)
	case "allow":
		resp.Message, err = g.WhitelistAdd(req.IP)
	case "disallow":
		resp.Message, err = g.WhitelistDel(req.IP)
	default:
		err = fmt.Errorf("unknown command %q", req.Cmd)
	}
	if err != nil {
		resp = Response{Error: err.Error()}
	}
	_ = json.NewEncoder(c).Encode(&resp)
}

// Call sends one request to the daemon.
func Call(path string, req Request) (*Response, error) {
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied on %s (run with sudo)", path)
		}
		return nil, fmt.Errorf("cannot reach sshshield daemon at %s (is the service running?): %w", path, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(&req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}
