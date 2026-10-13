package boot

import (
	"encoding/hex"
	"os"
	"testing"
)

func capturedRequest(t *testing.T) ReplayRequest {
	t.Helper()
	log, err := os.ReadFile("../../../testdata/boot/intel-CCEL.data.bin")
	if err != nil {
		t.Fatal(err)
	}
	// Recorded Intel SDK log and independently calculated replay values. The
	// fixture has no signed quote and is not proof of a boot attestation.
	values := []string{
		"8083cd6898cc52a90231cdf9c0532bf9513c40465c6f71e56cbe32ee2c11a9dfc030297ca3ca0f62477d6d1f610d3fdb",
		"6484f0d72c03521c0434553be34e8db8228b729e799666d2b7754085c77aa9981f5a440df3047194b24f212ff1160c1e",
		"c3e7ed9d7e909b29732f676d01dc63de869b049362b522a315cb042689670be07344c347cf85d985c7b928d4934e41e1",
	}
	req := ReplayRequest{Log: log[:2026]}
	for _, v := range values {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		req.Registers = append(req.Registers, b)
	}
	req.Registers = append(req.Registers, make([]byte, 48))
	return req
}

func TestCapturedCCELReplay(t *testing.T) {
	got, err := Replay(capturedRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if got.RegistersVerified != 4 || got.EventCount == 0 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestRejectsOmittedRuntimeHistoryAndChangedRegisters(t *testing.T) {
	for i := 0; i < 4; i++ {
		req := capturedRequest(t)
		req.Registers[i][0] ^= 1
		if _, err := Replay(req); err == nil {
			t.Fatalf("accepted changed RTMR%d", i)
		}
	}
	req := capturedRequest(t)
	req.Log = nil
	if _, err := Replay(req); err == nil {
		t.Fatal("accepted empty log")
	}
	req = capturedRequest(t)
	req.Registers = req.Registers[:3]
	if _, err := Replay(req); err == nil {
		t.Fatal("accepted omitted RTMR3")
	}
}
