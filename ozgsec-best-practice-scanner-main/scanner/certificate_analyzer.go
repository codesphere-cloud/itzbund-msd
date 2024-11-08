package scanner

import (
	"context"
	"crypto/dsa" // nolint: staticcheck // dsa is needed for the rsa.PublicKey type switch
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/concurrency"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

type certificateAnalyzer struct {
}

func NewCertificateAnalyzer() analyzer[*tls.ConnectionState] {
	return &certificateAnalyzer{}
}

/*
IMMEDIATE ACTION REQUIRED CHECK

	(if a REQUIRED spec is not met, the call to immediate action MUST be shown to the user)

REQUIRED: Certificate is not expired
REQUIRED: The certificates validity period does NOT start in the future
*/
func validCertificate(cert *x509.Certificate) AnalysisResult {
	start := time.Now()
	// check if the cert is expired
	if cert.NotAfter.Before(time.Now()) {
		return NewAnalysisResult(Failure, map[string]any{
			"expired": true,
		}, nil, nil, time.Since(start))
	}
	// check if the cert is not yet valid
	if cert.NotBefore.After(time.Now()) {
		return NewAnalysisResult(Failure, map[string]any{
			"notYetValid": true,
		}, nil, nil, time.Since(start))
	}

	return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
}

/*
IMMEDIATE ACTION REQUIRED CHECK

	(if a REQUIRED spec is not met, the call to immediate action MUST be shown to the user)

REQUIRED: The certificate chain is valid (all certificates are signed by the issuer) according

	to: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	Stating:
	  (a)  for all x in {1, ..., n-1}, the subject of certificate x is
	       the issuer of certificate x+1;
	  (b)  certificate 1 is issued by the trust anchor;
	  (c)  certificate n is the certificate to be validated (i.e., the
	       target certificate); and
	  (d)  for all x in {1, ..., n}, the certificate was valid at the
	       time in question.

	Note: The RFC includes checks that the certificate MUST NOT be revoked through OCSP or CRL.
	  This is not checked here. There will be an indipendent check for this.
*/
func validCertificateChain(certs []*x509.Certificate) AnalysisResult {
	start := time.Now()
	// inspect the whole chain of certificates
	for i := 0; i < len(certs)-1; i++ {
		if certs[i].Issuer.CommonName != certs[i+1].Subject.CommonName {
			return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
		}
		// check that the cert is not yet expired
		if certs[i].NotAfter.Before(time.Now()) {
			return NewAnalysisResult(Failure, map[string]any{
				"expired": true,
			}, nil, nil, time.Since(start))
		}
		// check that the cert is not yet valid
		if certs[i].NotBefore.After(time.Now()) {
			return NewAnalysisResult(Failure, map[string]any{
				"notYetValid": true,
			}, nil, nil, time.Since(start))
		}

		// verify the signature
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
		}
	}
	// check that the root cert is not yet expired
	if certs[len(certs)-1].NotAfter.Before(time.Now()) {
		return NewAnalysisResult(Failure, map[string]any{
			"expired": true,
		}, nil, nil, time.Since(start))
	}
	// check that the root cert is not yet valid
	if certs[len(certs)-1].NotBefore.After(time.Now()) {
		return NewAnalysisResult(Failure, map[string]any{
			"notYetValid": true,
		}, nil, nil, time.Since(start))
	}

	return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
}

/*
IMMEDIATE ACTION REQUIRED CHECK

	(if a REQUIRED spec is not met, the call to immediate action MUST be shown to the user)

REQUIRED in order:
 1. Check if the domain is in the subjectAltName extension of type dNSName (DNS:example.com)
 2. Check if the domain matches a wildcard pattern in the subjectAltName extension (DNS:*.example.com)
 3. Check if the domain is an exact match to the commonName field in the Subject field of the certificate.
 4. Check if the domain matches a wildcard pattern in the commonName field (e.g. *.example.com)

Note on wildcard patterns: "Names may contain the wildcard character * which is considered to match any single
domain name component or component fragment. E.g., *.a.com matches foo.a.com but not bar.foo.a.com. f*.com matches
foo.com but not bar.com."

As we require a domain, we will not validate ip addresses in the subjectAltName extension.

Source: https://datatracker.ietf.org/doc/html/rfc2818#section-3.1
*/
func matchesHostname(cert *x509.Certificate, hostname string) AnalysisResult {
	start := time.Now()
	if err := cert.VerifyHostname(hostname); err != nil {
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	}

	return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
}

func isStrongPrivateKey(cert *x509.Certificate) AnalysisResult {
	start := time.Now()
	// check if the private key is strong
	pubKey := cert.PublicKey
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// BSI TR-02102-1, Chapter 2.3.2
		if key.N.BitLen() < 3000 {
			return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
		}
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	case *dsa.PublicKey:
		// BSI TR-02102-1, Chapter 5.3.2
		if key.P.BitLen() < 3000 || key.Q.BitLen() < 250 {
			return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
		}
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	case *ecdsa.PublicKey:
		// BSI TR-02102-1
		if key.Curve.Params().BitSize < 250 {
			return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
		}
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	default:
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	}
}

func certificateTransparency(connectionState *tls.ConnectionState) AnalysisResult {
	start := time.Now()
	// check if the certificate is in the certificate transparency log
	for ex := range connectionState.PeerCertificates[0].Extensions {
		if connectionState.PeerCertificates[0].Extensions[ex].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
			// if it does exist, return true
			// TODO: Improve to really check if the certificate is in the log
			return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
		}
	}

	if connectionState.SignedCertificateTimestamps != nil {
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}

	if connectionState.OCSPResponse != nil {
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}

	return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
}

// holds the revocation lists based upon the CRLDistributionPoints
// the key is the CRLDistributionPoint and the value is the revocation list
var crlSet = cache.NewMaxMemoryMap[string, *x509.RevocationList](
	// only allow 100MB
	100 * 1024 * 1024,
)
var crlLock sync.Mutex

func fetchRevocationList(ctx context.Context, distributionPoint string) (*x509.RevocationList, error) {
	// fetch the revocation list if it is not already in the crlSet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, distributionPoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}
	return crl, nil
}

func isNotRevoked(ctx context.Context, certs []*x509.Certificate) AnalysisResult {
	start := time.Now()
	// check if the certificate is revoked
	channels := make([]<-chan DidPass, len(certs))
	for i, cert := range certs {
		channels[i] = concurrency.WrapInChan(func() DidPass {
			if cert.IsCA {
				return Success
			}
			ch := make([]<-chan DidPass, 0)
			for _, crlDistributionPoint := range cert.CRLDistributionPoints {
				ch = append(ch, concurrency.WrapInChan(
					func() DidPass {
						// fetch the revocation list if it is not already in the crlSet
						if _, ok := crlSet.Get(crlDistributionPoint); !ok {
							cr, err := fetchRevocationList(ctx, crlDistributionPoint)
							if err != nil {
								return Unknown
							}
							// save the revocation list in the crlSet
							crlLock.Lock()
							crlSet.Set(crlDistributionPoint, cr)
							crlLock.Unlock()
						}

						list, _ := crlSet.Get(crlDistributionPoint)
						if list == nil || list.RevokedCertificateEntries == nil {
							return Unknown
						}
						for _, revoked := range list.RevokedCertificateEntries {
							if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
								return Failure
							}
						}
						return Success
					}))
			}

			if utils.Every(concurrency.Collect(ch...), func(didPass DidPass) bool {
				return didPass != Failure
			}) {
				return Success
			}
			return Failure
		})
	}
	if utils.Every(concurrency.Collect(channels...), func(didPass DidPass) bool {
		return didPass != Failure
	}) {
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}
	return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
}

// https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm
func isStrongSignatureAlgorithm(cert *x509.Certificate) AnalysisResult {
	start := time.Now()
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1:
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	default:
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}
}

func (c certificateAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		ValidCertificate,
		ValidCertificateChain,
		MatchesHostname,
		StrongPrivateKey,
		NotRevoked,
		StrongSignatureAlgorithm,
		CertificateTransparency,
	}
}
func (c certificateAnalyzer) ExtractCacheableFromResult(analyzedTarget Target, result map[AnalysisRuleId]AnalysisResult) map[string]map[AnalysisRuleId]AnalysisResult {
	return map[string]map[AnalysisRuleId]AnalysisResult{
		// the whole result is cacheable on the hostname.
		// it is fair to expect, that if another target is scanned on that host,
		// the certificate wont change, if the path is different
		analyzedTarget.URL.Hostname(): result,
	}
}

func (c certificateAnalyzer) GetCacheKeys(target Target) []string {
	return []string{
		target.URL.Hostname(),
	}
}

// an existing tls connection state can be provided to reuse it.
// if it is nil, a new connection will be established
func (i certificateAnalyzer) Analyze(ctx context.Context, target Target, state *tls.ConnectionState) (map[AnalysisRuleId]AnalysisResult, error) {
	// check the cache
	if cachedValue, err := target.Options.CachingLayer.Get(ctx, target.URL.Hostname()); err == nil {
		cached, err := getFromCache(cachedValue, i.GetAnalysisRuleIds())
		if err == nil {
			return cached, nil
		}
	}

	var s *tls.ConnectionState = state
	if s == nil {
		// get the certificate
		conn, err := tlsConnect(ctx, target, nil)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		var res = conn.(*tls.Conn).ConnectionState()
		s = &res
	} else {
		slog.Debug("reusing existing tls connection state")
	}

	certificate := s.PeerCertificates[0]
	res := map[AnalysisRuleId]AnalysisResult{
		NotRevoked:               maybeDoCheck(NotRevoked, target.Options, func() AnalysisResult { return isNotRevoked(ctx, s.PeerCertificates) }),
		ValidCertificate:         maybeDoCheck(ValidCertificate, target.Options, func() AnalysisResult { return validCertificate(certificate) }),
		ValidCertificateChain:    maybeDoCheck(ValidCertificateChain, target.Options, func() AnalysisResult { return validCertificateChain(s.PeerCertificates) }),
		MatchesHostname:          maybeDoCheck(MatchesHostname, target.Options, func() AnalysisResult { return matchesHostname(certificate, target.URL.Hostname()) }),
		StrongPrivateKey:         maybeDoCheck(StrongPrivateKey, target.Options, func() AnalysisResult { return isStrongPrivateKey(certificate) }),
		StrongSignatureAlgorithm: maybeDoCheck(StrongSignatureAlgorithm, target.Options, func() AnalysisResult { return isStrongSignatureAlgorithm(certificate) }),
		CertificateTransparency:  maybeDoCheck(CertificateTransparency, target.Options, func() AnalysisResult { return certificateTransparency(s) }),
	}

	// cache the result
	target.Options.CachingLayer.Set(ctx, target.URL.Hostname(), res, 1*time.Hour) // nolint It does not matter if the cache fails - it is just a cache
	return res, nil
}
