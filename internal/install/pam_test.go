package install

import (
	"strings"
	"testing"
)

func TestPAMLine(t *testing.T) {
	for _, in := range []string{
		"#%PAM-1.0\n\n@include common-auth\naccount required pam_nologin.so\n",
		"#%PAM-1.0\nauth       substack     password-auth\nauth include postlogin\n",
	} {
		out, err := addPAMLine(in)
		if err != nil {
			t.Fatal(err)
		}
		i, j := strings.Index(out, pamLine), strings.Index(out, "auth")
		if i < 0 || strings.Index(out, "@include") >= 0 && strings.Index(out, "@include") < i || j < i {
			t.Fatalf("hook not first in auth stack:\n%s", out)
		}
		if back := removePAMLine(out); back != in {
			t.Fatalf("remove did not restore the original:\n%q\n%q", back, in)
		}
	}
	if _, err := addPAMLine("account required pam_nologin.so\n"); err == nil {
		t.Fatal("expected error without an auth stack")
	}
}
