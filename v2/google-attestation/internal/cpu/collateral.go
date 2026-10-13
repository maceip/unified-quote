package cpu

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const intelRootCRLURL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

type capturedResponse struct {
	header map[string][]string
	body   []byte
}

// capturedGetter structurally implements Google's HTTPSGetter without any
// network client. Unknown URLs always fail; evidence cannot cause outbound
// requests, redirects, retries, or replacement collateral to be consulted.
type capturedGetter struct {
	responses map[string]capturedResponse
}

func (g *capturedGetter) Get(address string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), address)
}

func (g *capturedGetter) GetContext(ctx context.Context, address string) (map[string][]string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	response, exists := g.responses[address]
	if !exists {
		return nil, nil, errors.New("vendor verifier requested unavailable captured collateral")
	}
	header := make(map[string][]string, len(response.header))
	for k, v := range response.header {
		header[k] = append([]string(nil), v...)
	}
	return header, append([]byte(nil), response.body...), nil
}

// prepareCollateral enforces local PKIX/revocation/freshness restrictions and
// prepares exact captured responses for Google's signed TCB/QE appraisal. Its
// successful return is not a TCB or quote verification result.
func prepareCollateral(c TdxCollateral, pckDER [][]byte, fmspc string, floor uint64, now time.Time) (*capturedGetter, error) {
	fmspcBytes, err := hex.DecodeString(fmspc)
	if err != nil || len(fmspcBytes) != 6 || fmspc != strings.ToLower(fmspc) {
		return nil, errors.New("invalid Intel PCK FMSPC")
	}
	pck, err := strictIntelChain(pckDER, now)
	if err != nil {
		return nil, err
	}
	if len(pck) != 3 || pck[0].Subject.CommonName != "Intel SGX PCK Certificate" {
		return nil, errors.New("unsupported Intel PCK hierarchy")
	}
	var ca string
	switch pck[1].Subject.CommonName {
	case "Intel SGX PCK Platform CA":
		ca = "platform"
	case "Intel SGX PCK Processor CA":
		ca = "processor"
	default:
		return nil, errors.New("unsupported Intel PCK issuer")
	}
	tcb, err := strictIntelChain(c.TcbInfoSigningChain, now)
	if err != nil {
		return nil, err
	}
	qe, err := strictIntelChain(c.QeIdentitySigningChain, now)
	if err != nil {
		return nil, err
	}
	for _, chain := range [][]*x509.Certificate{tcb, qe} {
		if len(chain) != 2 || chain[0].Subject.CommonName != "Intel SGX TCB Signing" {
			return nil, errors.New("unsupported Intel collateral signing hierarchy")
		}
		if err := strictCRL(c.RootCACRL, chain[0], chain[1], now); err != nil {
			return nil, err
		}
	}
	if err := strictCRL(c.RootCACRL, pck[1], pck[2], now); err != nil {
		return nil, err
	}
	if err := strictCRL(c.PckCRL, pck[0], pck[1], now); err != nil {
		return nil, err
	}
	if err := documentPolicy(c.TcbInfoJSON, "tcbInfo", floor, now); err != nil {
		return nil, err
	}
	if err := documentPolicy(c.QeIdentityJSON, "enclaveIdentity", floor, now); err != nil {
		return nil, err
	}
	return &capturedGetter{responses: map[string]capturedResponse{
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=" + fmspc: {
			header: map[string][]string{"Tcb-Info-Issuer-Chain": {issuerHeader(c.TcbInfoSigningChain)}},
			body:   c.TcbInfoJSON,
		},
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity": {
			header: map[string][]string{"Sgx-Enclave-Identity-Issuer-Chain": {issuerHeader(c.QeIdentitySigningChain)}},
			body:   c.QeIdentityJSON,
		},
		fmt.Sprintf("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=%s&encoding=der", ca): {
			header: map[string][]string{"Sgx-Pck-Crl-Issuer-Chain": {issuerHeader(pckDER[1:])}},
			body:   c.PckCRL,
		},
		intelRootCRLURL: {body: c.RootCACRL},
	}}, nil
}

func issuerHeader(chain [][]byte) string {
	var raw []byte
	for _, der := range chain {
		raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return url.QueryEscape(string(raw))
}
