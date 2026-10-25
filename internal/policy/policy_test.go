package policy

import (
	"agentexec/internal/model"
	"testing"
)

func TestAdmissionRejectsUnsafeRequests(t *testing.T) {
	p := Default()
	tests := []model.Request{
		{}, {Argv: []string{"python3"}}, {Argv: []string{"/usr/bin/python3", "x\x00y"}},
		{Argv: []string{"/bin/sh"}, TimeoutMS: 30001},
		{Argv: []string{"/bin/sh"}, Files: map[string]string{"../escape": "x"}},
		{Argv: []string{"/bin/sh"}, Files: map[string]string{"/etc/passwd": "x"}},
		{Argv: []string{"/bin/sh"}, Files: map[string]string{"a\\b": "x"}},
		{Argv: []string{"/bin/sh"}, Files: map[string]string{"a": "x", "a/b": "y"}},
		{Argv: []string{"/bin/sh"}, Files: map[string]string{"A.py": "x", "a.py": "y"}},
	}
	for i, r := range tests {
		if _, err := p.Normalize(r); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
func TestNormalizeCopiesInput(t *testing.T) {
	r := model.Request{Argv: []string{"/bin/sh"}, Files: map[string]string{"scripts/main.py": "ok"}}
	out, err := Default().Normalize(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Argv[0] = "/bad"
	r.Files["scripts/main.py"] = "changed"
	if out.Argv[0] != "/bin/sh" || out.Files["scripts/main.py"] != "ok" || out.TimeoutMS != 10000 {
		t.Fatal("admitted request was mutable")
	}
}
func FuzzValidFileName(f *testing.F) {
	for _, s := range []string{"a.py", "../x", "a/b", "C:\\x", "a//b", "a/../../z", "a\x00b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidFileName(s) {
			p := Default()
			if _, err := p.Normalize(model.Request{Argv: []string{"/bin/sh"}, Files: map[string]string{s: "x"}}); err != nil {
				t.Fatal(err)
			}
		}
	})
}
