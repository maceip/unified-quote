package cpu

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCapturedGetterHasNoNetworkFallbackOrMutableCache(t *testing.T) {
	g := &capturedGetter{responses: map[string]capturedResponse{
		intelRootCRLURL: {header: map[string][]string{"Key": {"original"}}, body: []byte("captured")},
	}}
	header, body, err := g.Get(intelRootCRLURL)
	if err != nil {
		t.Fatal(err)
	}
	header["Key"][0] = "changed"
	body[0] = '!'
	header, body, err = g.Get(intelRootCRLURL)
	if err != nil || header["Key"][0] != "original" || string(body) != "captured" {
		t.Fatal("returned bytes mutated the captured evidence")
	}
	for _, address := range []string{"http://127.0.0.1/", "file:///etc/passwd", intelRootCRLURL + "?x=1"} {
		if _, _, err := g.Get(address); err == nil {
			t.Fatal("unknown URL accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := g.GetContext(ctx, intelRootCRLURL); err == nil {
		t.Fatal("cancelled request continued")
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "tdx-collateral", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func captureTime() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

func TestIntelPinnedPathAndFreshCRL(t *testing.T) {
	chain := [][]byte{fixture(t, "tcb-signer-0.der"), fixture(t, "tcb-signer-1.der")}
	certs, err := strictIntelChain(chain, captureTime())
	if err != nil {
		t.Fatal(err)
	}
	crl := fixture(t, "root.crl.der")
	if err := strictCRL(crl, certs[0], certs[1], captureTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := strictIntelChain(chain, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired pinned chain accepted")
	}
	if _, err := strictIntelChain([][]byte{chain[0], chain[0]}, captureTime()); err == nil {
		t.Fatal("signing leaf substituted for pinned root")
	}
	for _, now := range []time.Time{time.Unix(1, 0), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := strictCRL(crl, certs[0], certs[1], now); err == nil {
			t.Fatal("future or expired CRL accepted")
		}
	}
	crl[len(crl)-1] ^= 1
	if err := strictCRL(crl, certs[0], certs[1], captureTime()); err == nil {
		t.Fatal("tampered signed CRL accepted")
	}
}

func TestIntelDocumentFreshnessAndRollback(t *testing.T) {
	for _, doc := range []struct{ file, object string }{{"tcb-info.json", "tcbInfo"}, {"qe-identity.json", "enclaveIdentity"}} {
		raw := fixture(t, doc.file)
		if err := documentPolicy(raw, doc.object, 20, captureTime()); err != nil {
			t.Fatal(err)
		}
		for _, now := range []time.Time{time.Unix(1, 0), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)} {
			if err := documentPolicy(raw, doc.object, 20, now); err == nil {
				t.Fatal("future or expired signed document accepted")
			}
		}
		if err := documentPolicy(raw, doc.object, ^uint64(0), captureTime()); err == nil {
			t.Fatal("TCB evaluation rollback accepted")
		}
	}
}

func TestDuplicateJSONNeverPromoted(t *testing.T) {
	for _, raw := range []string{
		`{"tcbInfo":{"x":1,"x":2},"signature":"00"}`,
		`{"tcbInfo":{},"tcbInfo":{},"signature":"00"}`,
		`{"array":[{"x":1,"x":2}]}`,
		`{} {}`,
	} {
		if err := uniqueJSON([]byte(raw)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %s", raw)
		}
	}
	if err := uniqueJSON([]byte(`{"x":[{"a":1},{"a":2}],"y":null}`)); err != nil {
		t.Fatal(err)
	}
}

// These are explicitly unsigned framing vectors. They can pass envelope bounds
// but cannot create a VerifyResult or substitute for Google quote verification.
func framedQuote(version, bodyType uint16, bodySize uint32) []byte {
	offset := 48 + 584
	if version == 5 {
		offset = 54 + int(bodySize)
	}
	raw := make([]byte, offset+5)
	binary.LittleEndian.PutUint16(raw, version)
	if version == 5 {
		binary.LittleEndian.PutUint16(raw[48:50], bodyType)
		binary.LittleEndian.PutUint32(raw[50:54], bodySize)
	}
	binary.LittleEndian.PutUint32(raw[offset:offset+4], 1)
	return raw
}

func TestExactV4V5Framing(t *testing.T) {
	for _, tc := range []struct {
		version, bodyType uint16
		bodySize          uint32
		tdx               string
	}{
		{4, 0, 584, "1.0"}, {5, 2, 584, "1.0"}, {5, 3, 648, "1.5"},
	} {
		raw := framedQuote(tc.version, tc.bodyType, tc.bodySize)
		version, tdx, err := checkQuoteEnvelope(raw)
		if err != nil || version != tc.version || tdx != tc.tdx {
			t.Fatalf("framing rejected: %d %s %v", version, tdx, err)
		}
		if _, _, err := checkQuoteEnvelope(append(raw, 0)); err == nil {
			t.Fatal("driver buffer padding accepted")
		}
		if _, _, err := checkQuoteEnvelope(raw[:len(raw)-2]); err == nil {
			t.Fatal("truncated signature length accepted")
		}
		if tc.version == 5 {
			binary.LittleEndian.PutUint32(raw[50:54], ^uint32(0))
			if _, _, err := checkQuoteEnvelope(raw); err == nil {
				t.Fatal("oversized v5 descriptor accepted")
			}
		}
	}
}
