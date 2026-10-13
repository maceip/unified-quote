package wire

import "testing"

func TestRejectsAmbiguousMessages(t *testing.T) {
	for _, raw := range []string{`{"version":1,"version":2}`, `{"version":1} {}`, `{"version":1,"unknown":2}`} {
		var out struct {
			Version int `json:"version"`
		}
		if Decode([]byte(raw), &out) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
