package strictjson

import (
	"strings"
	"testing"
)

func TestRejectAmbiguousJSON(t *testing.T) {
	for _, data := range []string{`{"name":"a","name":"b"}`, `{"name":"a","extra":true}`, `{"name":"a"} {}`, `{"name":`, strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		var dst struct {
			Name string `json:"name"`
		}
		if Decode([]byte(data), &dst) == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
func TestAccept(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := Decode([]byte(`{"name":"a"}`), &dst); err != nil || dst.Name != "a" {
		t.Fatal(err)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { var v any; _ = Decode(b, &v) })
}
