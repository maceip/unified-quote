// Package boot uses Google's TCG replay implementation with explicit coverage
// checks. Register values must be authenticated by the calling CPU verifier.
package boot

import (
	"bytes"
	_ "crypto/sha512"
	"fmt"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

type ReplayRequest struct {
	Log       []byte   `json:"log"`
	Registers [][]byte `json:"registers"`
}
type ReplayResult struct {
	EventCount        int `json:"event_count"`
	RegistersVerified int `json:"registers_verified"`
}

func init() {
	// Upstream can inject inferred ExitBootServices events on a failed replay.
	// Our policy permits only exact supplied evidence, so disable this behavior.
	tcg.EventlogWorkarounds = nil
}

func Replay(req ReplayRequest) (*ReplayResult, error) {
	if len(req.Log) == 0 || len(req.Log) > 16*1024*1024 || len(req.Registers) != 4 {
		return nil, fmt.Errorf("requires a bounded nonempty log and all four RTMRs")
	}
	bank := register.RTMRBank{}
	for i, value := range req.Registers {
		if len(value) != 48 {
			return nil, fmt.Errorf("RTMR%d must contain 48 bytes", i)
		}
		bank.RTMRs = append(bank.RTMRs, register.RTMR{Index: i, Digest: value})
	}
	// Rust removes validated uniform ACPI padding before invoking this adapter.
	// Accept no padding here, so it cannot conceal an unparsed trailing event.
	log, err := tcg.ParseEventLog(req.Log, tcg.ParseOpts{AllowPadding: false})
	if err != nil {
		return nil, err
	}
	events := log.Events(register.HashSHA384)
	if len(events) > 65536 {
		return nil, fmt.Errorf("event count exceeds limit")
	}
	seen := [4]bool{}
	for _, e := range events {
		if len(e.Data) > 4*1024*1024 {
			return nil, fmt.Errorf("event size exceeds limit")
		}
		if e.Type == tcg.EventType(3) {
			continue
		}
		if e.Index < 1 || e.Index > 4 || len(e.Digest) != 48 {
			return nil, fmt.Errorf("event lacks an enrolled SHA384 RTMR")
		}
		seen[e.Index-1] = true
	}
	// Upstream regards a register without events as successful even if its
	// supplied value is nonzero. Require the actual unextended value explicitly.
	for i, value := range req.Registers {
		if !seen[i] && !bytes.Equal(value, make([]byte, 48)) {
			return nil, fmt.Errorf("RTMR%d has no events but is nonzero", i)
		}
	}
	verified, err := log.Verify(bank.MRs())
	if err != nil {
		return nil, err
	}
	return &ReplayResult{EventCount: len(verified), RegistersVerified: 4}, nil
}
