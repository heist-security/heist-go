package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/heist-security/heist-go/heist"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "API contract "+heist.APIVersion) {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	for _, tt := range []struct {
		args []string
		msg  string
	}{
		{[]string{"nope"}, `unknown command "nope"`},
		{[]string{"completion", "zhs"}, `unknown command "zhs"; did you mean zsh?`},
		{[]string{"completion"}, "expected a command"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(tt.args, nil, &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tt.msg) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tt.args, code, stdout.String(), stderr.String())
		}
	}
}
