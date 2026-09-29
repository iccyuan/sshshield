package install

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// PAMFile is the sshd PAM stack that the password hook is added to.
const PAMFile = "/etc/pam.d/sshd"

// The hook only reads the password; "optional" + "quiet" means it can never
// block or change a login, even if sshshield is missing or broken.
const pamLine = "auth optional pam_exec.so quiet expose_authtok " + BinPath + " pam-hook"

const pamMarker = BinPath + " pam-hook"

// The hook must run before the first module that checks the password.
var pamAuthStart = regexp.MustCompile(`^\s*(auth\s|@include\s+common-auth)`)

// PAMEnabled reports whether the password hook is in the sshd PAM stack.
func PAMEnabled() (bool, error) {
	b, err := os.ReadFile(PAMFile)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), pamMarker), nil
}

// PAMEnable adds the password hook in front of the sshd auth stack.
func PAMEnable() error {
	if err := checkRoot(); err != nil {
		return err
	}
	b, err := os.ReadFile(PAMFile)
	if err != nil {
		return err
	}
	if strings.Contains(string(b), pamMarker) {
		return nil
	}
	out, err := addPAMLine(string(b))
	if err != nil {
		return err
	}
	bak := PAMFile + ".sshshield.bak"
	if _, err := os.Stat(bak); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(bak, b, 0o644); err != nil {
			return err
		}
	}
	return writePAM(out)
}

// PAMDisable removes the password hook; a missing hook is not an error.
func PAMDisable() error {
	if err := checkRoot(); err != nil {
		return err
	}
	b, err := os.ReadFile(PAMFile)
	if err != nil {
		return err
	}
	out := removePAMLine(string(b))
	if out == string(b) {
		return nil
	}
	return writePAM(out)
}

func addPAMLine(s string) (string, error) {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		if pamAuthStart.MatchString(l) {
			ins := "# sshshield: record attempted passwords (sshshield pam off to remove)\n" + pamLine + "\n"
			return strings.Join(lines[:i], "") + ins + strings.Join(lines[i:], ""), nil
		}
	}
	return "", fmt.Errorf("%s 中没有找到 auth 配置", PAMFile)
}

func removePAMLine(s string) string {
	var kept []string
	for _, l := range strings.SplitAfter(s, "\n") {
		if strings.Contains(l, pamMarker) || strings.HasPrefix(l, "# sshshield:") {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "")
}

// writePAM replaces the file atomically so sshd never reads a half-written stack.
func writePAM(s string) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(PAMFile); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := PAMFile + ".sshshield.tmp"
	if err := os.WriteFile(tmp, []byte(s), mode); err != nil {
		return err
	}
	return os.Rename(tmp, PAMFile)
}
