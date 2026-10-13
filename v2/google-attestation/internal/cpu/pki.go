package cpu

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Same DER fingerprint as the existing Rust CPU verifier. Evidence never
// supplies a new trust anchor: its final certificate must match this pin.
const intelRootSHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

// strictIntelChain adds this project's algorithm, purpose, root-lifetime and
// extension restrictions to the Go standard library's RFC 5280 path verifier.
// It is a guard around upstream vendor appraisal, not a replacement for it.
func strictIntelChain(derChain [][]byte, now time.Time) ([]*x509.Certificate, error) {
	if len(derChain) < 2 || len(derChain) > 3 {
		return nil, errors.New("unsupported Intel certificate path length")
	}
	certs := make([]*x509.Certificate, 0, len(derChain))
	remaining := maxChainBytes
	seen := make(map[string]bool)
	for i, der := range derChain {
		if len(der) == 0 || len(der) > remaining {
			return nil, errors.New("Intel certificate path size outside limit")
		}
		remaining -= len(der)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if cert.Version != 3 || cert.SerialNumber.Sign() <= 0 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, errors.New("Intel certificate version, serial or validity is unacceptable")
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			return nil, errors.New("Intel certificate requires P256 and ECDSA-SHA256")
		}
		if len(cert.UnhandledCriticalExtensions) != 0 {
			return nil, errors.New("Intel certificate has unhandled critical extensions")
		}
		criticalCA := false
		ekuPresent := false
		exts := make(map[string]bool)
		for _, ext := range cert.Extensions {
			oid := ext.Id.String()
			if exts[oid] {
				return nil, errors.New("duplicate Intel certificate extension")
			}
			exts[oid] = true
			switch oid {
			case "2.5.29.19":
				criticalCA = ext.Critical
			case "2.5.29.37":
				ekuPresent = true
			case "2.5.29.30", "2.5.29.33", "2.5.29.36", "2.5.29.54":
				return nil, errors.New("unsupported Intel certificate name/policy constraints")
			}
			if ext.Critical {
				switch oid {
				case "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.14", "2.5.29.35":
				default:
					return nil, fmt.Errorf("unsupported critical Intel certificate extension %s", oid)
				}
			}
		}
		if ekuPresent {
			unrestricted := false
			for _, eku := range cert.ExtKeyUsage {
				unrestricted = unrestricted || eku == x509.ExtKeyUsageAny
			}
			if !unrestricted {
				return nil, errors.New("Intel certificate EKU excludes unrestricted attestation use")
			}
		}
		if i == 0 {
			if cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
				return nil, errors.New("Intel signing leaf has invalid CA or key-usage constraints")
			}
		} else if !cert.BasicConstraintsValid || !cert.IsCA || !criticalCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("Intel issuer lacks critical CA and keyCertSign constraints")
		}
		fingerprint := sha256.Sum256(der)
		if seen[string(fingerprint[:])] {
			return nil, errors.New("repeated Intel certificate in path")
		}
		seen[string(fingerprint[:])] = true
		certs = append(certs, cert)
	}
	root := certs[len(certs)-1]
	digest := sha256.Sum256(root.Raw)
	if hex.EncodeToString(digest[:]) != intelRootSHA256 || !bytes.Equal(root.RawSubject, root.RawIssuer) {
		return nil, errors.New("Intel root does not match compiled trust anchor")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, err
	}
	for i := 0; i < len(certs)-1; i++ {
		child, issuer := certs[i], certs[i+1]
		if !bytes.Equal(child.RawIssuer, issuer.RawSubject) || (len(child.AuthorityKeyId) != 0 && !bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId)) {
			return nil, errors.New("Intel certificate issuer or authority key identifier mismatch")
		}
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return nil, err
		}
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, cert := range certs[1 : len(certs)-1] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, err
	}
	return certs, nil
}

// strictCRL requires a complete, fresh, direct CRL covering this exact issuer.
// A missing/stale/unsupported list is an error, never an unknown-as-good result.
func strictCRL(raw []byte, subject, issuer *x509.Certificate, now time.Time) error {
	if subject == nil || issuer == nil || len(raw) == 0 || len(raw) > maxCRLBytes {
		return errors.New("missing or oversized Intel revocation evidence")
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || !bytes.Equal(subject.RawIssuer, issuer.RawSubject) || len(crl.AuthorityKeyId) == 0 || !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("Intel CRL issuer or authority key identifier mismatch")
	}
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) || !crl.ThisUpdate.Before(crl.NextUpdate) {
		return errors.New("Intel CRL is future, expired, or lacks a validity window")
	}
	if crl.Number == nil || crl.Number.Sign() < 0 || crl.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return errors.New("unsupported Intel CRL number or algorithm")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return err
	}
	seenExtensions := make(map[string]bool)
	for _, ext := range crl.Extensions {
		oid := ext.Id.String()
		if seenExtensions[oid] {
			return errors.New("duplicate Intel CRL extension")
		}
		seenExtensions[oid] = true
		switch oid {
		case "2.5.29.35", "2.5.29.20": // AKI and CRL number
		case "2.5.29.27", "2.5.29.28", "2.5.29.46":
			return errors.New("delta or scoped Intel CRL is unsupported")
		default:
			if ext.Critical {
				return errors.New("unhandled critical Intel CRL extension")
			}
		}
	}
	if len(crl.RevokedCertificateEntries) > 100000 {
		return errors.New("Intel CRL entry count outside limit")
	}
	serials := make(map[string]bool)
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || serials[entry.SerialNumber.String()] {
			return errors.New("invalid or duplicate Intel CRL serial")
		}
		serials[entry.SerialNumber.String()] = true
		if entry.ReasonCode == 8 { // removeFromCRL requires a delta profile.
			return errors.New("removeFromCRL is unsupported in a complete Intel CRL")
		}
		entryOIDs := make(map[string]bool)
		for _, ext := range entry.Extensions {
			oid := ext.Id.String()
			if entryOIDs[oid] || oid == "2.5.29.29" || ext.Critical {
				return errors.New("duplicate, indirect, or critical Intel CRL entry extension")
			}
			entryOIDs[oid] = true
		}
		if entry.SerialNumber.Cmp(subject.SerialNumber) == 0 {
			return errors.New("Intel certificate is revoked")
		}
	}
	return nil
}
