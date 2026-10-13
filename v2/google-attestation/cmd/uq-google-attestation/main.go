// uq-google-attestation is a local adapter, invoked by the Rust verifier after
// its input and policy checks. It does not offer a network service.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ZUNFTMAX/zmax-universal-attestations/v2/google-attestation/internal/boot"
	"github.com/ZUNFTMAX/zmax-universal-attestations/v2/google-attestation/internal/wire"
)

type request struct {
	Version   uint32          `json:"version"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}
type response struct {
	Version       uint32 `json:"version"`
	RequestSHA256 string `json:"request_sha256"`
	Result        any    `json:"result,omitempty"`
	Error         string `json:"error,omitempty"`
}

func dispatch(raw []byte) (any, error) {
	var req request
	if err := wire.Decode(raw, &req); err != nil {
		return nil, err
	}
	if req.Version != 1 {
		return nil, fmt.Errorf("unsupported protocol version")
	}
	switch req.Operation {
	case "tdx_replay":
		var payload boot.ReplayRequest
		if err := wire.Decode(req.Payload, &payload); err != nil {
			return nil, err
		}
		return boot.Replay(payload)
	default:
		return nil, fmt.Errorf("unsupported operation %q", req.Operation)
	}
}

func run() int {
	if len(os.Args) != 2 || os.Args[1] != "--stdio-v1" {
		fmt.Fprintln(os.Stderr, "usage: uq-google-attestation --stdio-v1")
		return 2
	}
	const maxRequest = 48 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequest+1))
	if err != nil || len(raw) > maxRequest {
		fmt.Fprintln(os.Stderr, "invalid or oversized request")
		return 2
	}
	digest := sha256.Sum256(raw)
	out := response{Version: 1, RequestSHA256: hex.EncodeToString(digest[:])}
	out.Result, err = dispatch(raw)
	status := 0
	if err != nil {
		out.Result = nil
		out.Error = err.Error()
		status = 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return 2
	}
	return status
}

func main() { os.Exit(run()) }
