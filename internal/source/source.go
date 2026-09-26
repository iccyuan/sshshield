// Package source streams sshd log lines from journald or a syslog file.
package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

var candidateFiles = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"}

// Resolve picks the concrete source ("journal" or "file") and file path for mode "auto".
func Resolve(mode, file string) (string, string, error) {
	switch mode {
	case "journal":
		return "journal", "", nil
	case "file":
		if file == "" {
			file = firstExisting()
		}
		if file == "" {
			return "", "", fmt.Errorf("no auth log file found, set log_file")
		}
		return "file", file, nil
	case "", "auto":
		if _, err := exec.LookPath("journalctl"); err == nil && isSystemd() {
			return "journal", "", nil
		}
		if f := firstExisting(); f != "" {
			return "file", f, nil
		}
		return "", "", fmt.Errorf("neither journald nor an auth log file is available")
	}
	return "", "", fmt.Errorf("unknown source %q", mode)
}

func isSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func firstExisting() string {
	for _, f := range candidateFiles {
		if st, err := os.Stat(f); err == nil && !st.IsDir() {
			return f
		}
	}
	return ""
}

// Run sends lines to out until ctx is done, restarting the underlying reader on errors.
func Run(ctx context.Context, kind, file string, out chan<- string) {
	for ctx.Err() == nil {
		var err error
		if kind == "journal" {
			err = runJournal(ctx, out)
		} else {
			err = tailFile(ctx, file, out)
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("log source %s stopped: %v; restarting in 3s", kind, err)
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

func runJournal(ctx context.Context, out chan<- string) error {
	// Newer OpenSSH (9.8+) logs auth failures from sshd-session; match both identifiers.
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-o", "cat",
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case out <- sc.Text():
		case <-ctx.Done():
		}
	}
	_ = cmd.Wait()
	if err := sc.Err(); err != nil {
		return err
	}
	return fmt.Errorf("journalctl exited")
}

// tailFile follows path from its current end, reopening it after log rotation.
func tailFile(ctx context.Context, path string, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	r := bufio.NewReader(f)
	var partial strings.Builder
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		for {
			chunk, err := r.ReadString('\n')
			partial.WriteString(chunk)
			if err != nil {
				break
			}
			line := strings.TrimRight(partial.String(), "\r\n")
			partial.Reset()
			select {
			case out <- line:
			case <-ctx.Done():
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		cur, err1 := f.Stat()
		disk, err2 := os.Stat(path)
		if err2 != nil {
			continue // rotated away, new file not created yet
		}
		pos, _ := f.Seek(0, io.SeekCurrent)
		if err1 != nil || !os.SameFile(cur, disk) || disk.Size() < pos {
			nf, err := os.Open(path)
			if err != nil {
				continue
			}
			f.Close()
			f = nf
			r = bufio.NewReader(f)
			partial.Reset()
		}
	}
}
