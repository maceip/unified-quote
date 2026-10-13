// Package cpu contains the strict policy boundary for Google CPU-attestation
// backends. Byte slices use JSON base64 strings. Inputs are evidence until both
// the vendor verifier and the independent policy checks have succeeded.
package cpu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	MaxQuoteBytes = 8 * 1024 * 1024
	maxJSONBytes  = 1024 * 1024
	maxCRLBytes   = 4 * 1024 * 1024
	maxChainBytes = 256 * 1024
)

// TdxCollateral preserves original signed PCS document bytes. Certificate
// chains contain DER certificates in leaf-to-root order, including the root.
type TdxCollateral struct {
	TcbInfoJSON            []byte   `json:"tcb_info_json"`
	TcbInfoSigningChain    [][]byte `json:"tcb_info_signing_chain"`
	QeIdentityJSON         []byte   `json:"qe_identity_json"`
	QeIdentitySigningChain [][]byte `json:"qe_identity_signing_chain"`
	RootCACRL              []byte   `json:"root_ca_crl"`
	PckCRL                 []byte   `json:"pck_crl"`
}

// TdxPolicy is independent verifier policy, never attester-supplied collateral.
type TdxPolicy struct {
	MinimumTCBEvaluationDataNumber uint64 `json:"minimum_tcb_evaluation_data_number"`
}

type VerifyRequest struct {
	Quote               []byte        `json:"quote"`
	ExpectedReportData  []byte        `json:"expected_report_data"`
	ExpectedMeasurement []byte        `json:"expected_measurement"`
	Collateral          TdxCollateral `json:"collateral"`
	Policy              TdxPolicy     `json:"policy"`
}

// VerifyResult must be constructed only after Google verification and all
// additional policy guards succeed. Parsing alone never creates this result.
type VerifyResult struct {
	Measurements map[string][]byte `json:"measurements"`
	QuoteVersion uint16            `json:"quote_version"`
	TdxVersion   string            `json:"tdx_version"`
	TCBStatus    string            `json:"tcb_status"`
}

type CollectRequest struct {
	Platform   string `json:"platform"`
	Transport  string `json:"transport"`
	ReportData []byte `json:"report_data"`
}

// CollectResult contains unverified evidence. Collection does not imply
// authenticity, policy admission, or a successful hardware qualification run.
type CollectResult struct {
	Quote []byte `json:"quote"`
}

func (r *VerifyRequest) validate(now time.Time) error {
	if now.IsZero() || now.Unix() <= 0 {
		return errors.New("trusted verifier clock is invalid")
	}
	if len(r.ExpectedReportData) != 64 {
		return errors.New("expected_report_data must contain exactly 64 bytes")
	}
	if len(r.ExpectedMeasurement) != 48 || bytes.Equal(r.ExpectedMeasurement, make([]byte, 48)) {
		return errors.New("expected_measurement must contain a nonzero 48-byte MRTD")
	}
	if r.Policy.MinimumTCBEvaluationDataNumber == 0 {
		return errors.New("independent TCB evaluation-data minimum must be nonzero")
	}
	if _, _, err := checkQuoteEnvelope(r.Quote); err != nil {
		return err
	}
	for _, doc := range [][]byte{r.Collateral.TcbInfoJSON, r.Collateral.QeIdentityJSON} {
		if len(doc) == 0 || len(doc) > maxJSONBytes {
			return errors.New("Intel signed JSON size outside limit")
		}
	}
	for _, crl := range [][]byte{r.Collateral.RootCACRL, r.Collateral.PckCRL} {
		if len(crl) == 0 || len(crl) > maxCRLBytes {
			return errors.New("Intel CRL size outside limit")
		}
	}
	for _, chain := range [][][]byte{r.Collateral.TcbInfoSigningChain, r.Collateral.QeIdentitySigningChain} {
		if len(chain) != 2 {
			return errors.New("Intel collateral signing chain must contain signing leaf and root")
		}
		total := 0
		for _, der := range chain {
			if len(der) == 0 || len(der) > maxChainBytes-total {
				return errors.New("Intel signing chain size outside limit")
			}
			total += len(der)
		}
	}
	return nil
}

// checkQuoteEnvelope rejects trailing driver-buffer data and bounds the v5
// descriptor before calling the upstream parser. It does not authenticate it.
func checkQuoteEnvelope(raw []byte) (version uint16, tdxVersion string, err error) {
	if len(raw) < 48 || len(raw) > MaxQuoteBytes {
		return 0, "", errors.New("TDX quote size outside limit")
	}
	version = binary.LittleEndian.Uint16(raw[:2])
	lengthOffset := 48 + 584
	tdxVersion = "1.0"
	switch version {
	case 4:
	case 5:
		if len(raw) < 54 {
			return 0, "", errors.New("truncated TDX v5 descriptor")
		}
		bodyType := binary.LittleEndian.Uint16(raw[48:50])
		bodySize := binary.LittleEndian.Uint32(raw[50:54])
		switch {
		case bodyType == 2 && bodySize == 584:
		case bodyType == 3 && bodySize == 648:
			tdxVersion = "1.5"
		default:
			return 0, "", errors.New("unsupported TDX v5 body type or size")
		}
		lengthOffset = 54 + int(bodySize)
	default:
		return 0, "", fmt.Errorf("unsupported TDX quote version %d", version)
	}
	if len(raw) < lengthOffset+4 {
		return 0, "", errors.New("truncated TDX signed-data length")
	}
	signedSize := binary.LittleEndian.Uint32(raw[lengthOffset : lengthOffset+4])
	if signedSize == 0 || uint64(signedSize) != uint64(len(raw)-lengthOffset-4) {
		return 0, "", errors.New("TDX signed-data length mismatch or trailing bytes")
	}
	return version, tdxVersion, nil
}
