module github.com/ZUNFTMAX/zmax-universal-attestations/v2/google-attestation

go 1.25.0

require github.com/google/go-eventlog v0.0.2

require (
	github.com/beevik/etree v1.6.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/lestrrat-go/libxml2 v0.0.0-20260304224138-bb3877930cf7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/goxmldsig v1.6.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
)

require (
	github.com/google/go-nvattest-tools v0.0.0-20261009053956-1a098bebccd3
	github.com/google/go-tdx-guest v0.3.2-0.20261003001058-b0a2dd8100a0
	github.com/google/go-tpm v0.9.0 // indirect
	go.uber.org/multierr v1.11.0
	golang.org/x/sys v0.43.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/russellhaering/goxmldsig => github.com/atulpatildbz/goxmldsig v0.0.0-20260325075722-e806be5e3c3a

replace github.com/lestrrat-go/libxml2 => github.com/atulpatildbz/libxml2 v0.0.0-20260624132807-d06374c0f56f
