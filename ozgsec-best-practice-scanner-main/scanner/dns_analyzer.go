package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/concurrency"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

type domainAnalyzer struct {
	client *dns.Client
}

const (
	DmarcAvoidPolicyNone = "dmarcAvoidPolicyNone"
	DaneMissingStarttls  = "daneMissingStarttls"
)

func (d domainAnalyzer) dnssec(ctx context.Context, target Target) (bool, error) {
	checkTypes := []uint16{dns.TypeA}
	if target.SupportsIPV6() {
		// check if the AAAA record is signed as well
		checkTypes = append(checkTypes, dns.TypeAAAA)
	}

	for _, rType := range checkTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(target.URL.Hostname()), rType)
		m.SetEdns0(4096, true)
		msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")

		if err != nil {
			return false, err
		}

		if msg.Rcode != dns.RcodeSuccess || !msg.AuthenticatedData || msg.CheckingDisabled {
			return false, nil
		}
	}
	return true, nil
}

var probableDKIMHostnames = []string{
	"google._domainkey",
	"default._domainkey",
	"mail._domainkey",
}

func certificateMatchesTLSA(tlsConnectionState tls.ConnectionState, tlsa *dns.TLSA) bool {
	if tlsa == nil {
		return false
	}
	// the usage should be 2 or 3 - DANE-TA, or DANE-EE
	if tlsa.Usage != 2 && tlsa.Usage != 3 {
		return false
	}

	// check what needs to be validated.
	var toValidate []byte
	if tlsa.Selector == 0 {
		// we are looking at the full certificate
		toValidate = tlsConnectionState.PeerCertificates[0].Raw
	} else {
		// we are looking at the public key
		key := tlsConnectionState.PeerCertificates[0].PublicKey
		switch key := key.(type) {
		case *rsa.PublicKey:
			toValidate = key.N.Bytes()
		case *ecdsa.PublicKey:
			toValidate = elliptic.Marshal(key, key.X, key.Y) //nolint:all // todo: use the ecdh package instead of elliptic
		}
	}

	// check the matching type
	switch tlsa.MatchingType {
	case 1:
		// do a sha256 hash
		hash := sha256.Sum256(toValidate)
		// encode to hex
		return strings.EqualFold(hex.EncodeToString(hash[:]), tlsa.Certificate)
	case 2:
		// do a sha512 hash
		hash := sha512.Sum512(toValidate)
		return strings.EqualFold(hex.EncodeToString(hash[:]), tlsa.Certificate)
	default:
		// do a full match
		return strings.EqualFold(hex.EncodeToString(toValidate), tlsa.Certificate)
	}
}

// returns (starttls, dane)
func (d domainAnalyzer) verifyStartTLSAndDane(ctx context.Context, mx string, port string) (DidPass, DidPass) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", mx+":"+port)

	if err != nil {
		return Unknown, Unknown
	}

	c, err := smtp.NewClient(conn, mx)

	if err != nil {
		return Unknown, Unknown
	}
	defer c.Close()

	// issue explicit starttls command
	// this is not necessary for port 465 as it is already encrypted
	err = c.StartTLS(&tls.Config{
		InsecureSkipVerify: true, // nolint // we are just interested in the tls stack - not if the certificate is valid
	})
	tlsConnectionState, ok := c.TLSConnectionState()
	// this port was not able to upgrade the connection to an encrypted one
	if err != nil || !ok {
		return Failure, Failure
	} else {
		// starttls is already passed - lets check if dane is enabled as well.
		tlsaQ := new(dns.Msg)
		tlsaQ.SetQuestion(dns.Fqdn("_"+port+"._tcp."+mx), dns.TypeTLSA)
		// do the dns query
		tlsaMsg, _, err := d.client.ExchangeContext(ctx, tlsaQ, "8.8.8.8:53")
		if err != nil {
			return Success, Unknown
		}
		if tlsaMsg.Rcode != dns.RcodeSuccess {
			return Success, Unknown
		}

		if !ok {
			return Failure, Unknown
		}
		// check if the tlsa record is valid
		for _, answer := range tlsaMsg.Answer {
			if answer.Header().Rrtype == dns.TypeTLSA {
				if certificateMatchesTLSA(tlsConnectionState, answer.(*dns.TLSA)) {
					return Success, Success
				}
			}
		}
		return Success, Failure
	}
}

// do the starttls and dane check in a single function to avoid another starttls connection
func (d domainAnalyzer) starttlsAndDane(ctx context.Context, target Target) map[AnalysisRuleId]AnalysisResult {
	start := time.Now()
	// get the mx record of the target
	m := new(dns.Msg)
	hostname := strings.Replace(dns.Fqdn(target.URL.Hostname()), "www.", "", -1)
	m.SetQuestion(hostname, dns.TypeMX)
	msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return map[AnalysisRuleId]AnalysisResult{
			STARTTLS: NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
			DANE:     NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
		}
	}

	// check if the mx record exists
	if msg.Rcode != dns.RcodeSuccess {
		return map[AnalysisRuleId]AnalysisResult{
			STARTTLS: NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
			DANE:     NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
		}
	}

	var mxRecords []string
	// check if the mx record is valid
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeMX {
			mxRecords = append(mxRecords, answer.(*dns.MX).Mx)
		}
	}

	if len(mxRecords) == 0 {
		return map[AnalysisRuleId]AnalysisResult{
			STARTTLS: NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
			DANE:     NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)),
		}
	}

	portMap := map[string]map[AnalysisRuleId]DidPass{}
	var wg sync.WaitGroup
	wg.Add(len(mxRecords) * 2)
	mut := sync.Mutex{}
	// we are not testing port 465 as it is used for implicit tls
	// therefore it is already encrypted and does not support starttls
	for _, mxServer := range mxRecords {
		for _, port := range []string{"25", "587"} {
			go func(mxServer, port string) {
				defer wg.Done()
				starttls, dane := d.verifyStartTLSAndDane(ctx, mxServer, port)
				mut.Lock()
				portMap[mxServer+":"+port] = map[AnalysisRuleId]DidPass{
					STARTTLS: starttls,
					DANE:     dane,
				}
				mut.Unlock()
			}(mxServer, port)
		}
	}
	// wait for the completion of all goroutines
	wg.Wait()

	// reduce the results to a single result
	var starttls DidPass = Unknown
	var dane DidPass = Unknown

	daneActualValue := map[string]DidPass{}
	starttlsActualValue := map[string]DidPass{}

	for _, mxServer := range mxRecords {
		for _, port := range []string{"25", "587"} {
			starttlsActualValue[mxServer+":"+port] = portMap[mxServer+":"+port][STARTTLS]
			daneActualValue[mxServer+":"+port] = portMap[mxServer+":"+port][DANE]
			if portMap[mxServer+":"+port][STARTTLS] == Failure {
				starttls = Failure
			}
			if portMap[mxServer+":"+port][DANE] == Failure {
				dane = Failure
			}
			if portMap[mxServer+":"+port][STARTTLS] == Success {
				starttls = Success
			}
			if portMap[mxServer+":"+port][DANE] == Success {
				dane = Success
			}
		}
	}

	return map[AnalysisRuleId]AnalysisResult{
		STARTTLS: NewAnalysisResult(starttls, starttlsActualValue, nil, nil, time.Since(start)),
		DANE:     NewAnalysisResult(dane, daneActualValue, nil, nil, time.Since(start)),
	}
}

func (d domainAnalyzer) dmarc(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
	// fetch the txt dns records.
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_dmarc."+target.URL.Hostname()), dns.TypeTXT)
	msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")

	if err != nil {
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}

	// check if the dmarc record exists
	if msg.Rcode != dns.RcodeSuccess {
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	}

	// check if the dmarc record is valid
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			if strings.HasPrefix(answer.(*dns.TXT).Txt[0], "v=DMARC1") {
				// check if the policy contains none.
				if strings.Contains(answer.(*dns.TXT).Txt[0], "p=none") {
					return NewAnalysisResult(Success, map[string]string{
						"dmarc": answer.(*dns.TXT).Txt[0],
					}, nil, []string{DmarcAvoidPolicyNone}, time.Since(start))
				}
				return NewAnalysisResult(Success, map[string]string{
					"dmarc": answer.(*dns.TXT).Txt[0],
				}, nil, nil, time.Since(start))
			}
		}
	}
	return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
}

func (d domainAnalyzer) dkim(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
dkimHostnameLoop:
	for _, probableDKIMHostname := range probableDKIMHostnames {
		// fetch the txt dns records.
		m := new(dns.Msg)
		hostname := strings.Replace(target.URL.Hostname(), "www.", "", -1)
		m.SetQuestion(dns.Fqdn(probableDKIMHostname+"."+hostname), dns.TypeTXT)
		msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")
		if err != nil {
			return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
		}

		// check if the dkim record exists
		if msg.Rcode != dns.RcodeSuccess {
			continue dkimHostnameLoop
		}

		// check if the dkim record is valid
		for _, answer := range msg.Answer {
			if answer.Header().Rrtype == dns.TypeTXT {
				if strings.HasPrefix(answer.(*dns.TXT).Txt[0], "v=DKIM1") {
					return NewAnalysisResult(Success, map[string]string{
						"dkim": answer.(*dns.TXT).Txt[0],
					}, nil, nil, time.Since(start))
				}
			}
		}
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	}
	return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
}

func (d domainAnalyzer) spf(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
	// fetch the txt dns records.
	m := new(dns.Msg)
	hostname := strings.Replace(target.URL.Hostname(), "www.", "", -1)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
	msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}

	// check if the spf record exists
	if msg.Rcode != dns.RcodeSuccess {
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
	}

	// check if the spf record is valid
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			if strings.HasPrefix(answer.(*dns.TXT).Txt[0], "v=spf1") {
				return NewAnalysisResult(Success, map[string]string{
					"spf": answer.(*dns.TXT).Txt[0],
				}, nil, nil, time.Since(start))
			}
		}
	}
	return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))
}

/**
 *
 * @requirements
 * REQUIRED: The "CAA" records are present.
 * REQUIRED: The "CAA" flag is set to 0 (not critical).
 * REQUIRED: The "CAA" "issue" (value not ";") and/ or "issuewild" properties are present.
 * REQUIRED: If the "CAA" "iodef" property is present (mailto: or https://), it is valid.
 *
 * Base Format: CAA <flags> <tag> <value>
 * Example: CAA 0 issue "letsencrypt.org"
 * Example: CAA 0 issue "ca1.example.net; account=230123"
 * Example: CAA 0 issuewild "letsencrypt.org"
 * Example: CAA 0 iodef "mailto:opensource@neuland-homeland.de"
 * Example: CAA 0 iodef "https://iodef.example.com/"
 * Bad Example: CAA 0 issue ";"
 * Bad Example: CAA 1 issue "letsencrypt.org"
 * Malformed Example: CAA 0 issue "%%%%%"
 *
 */
func (d domainAnalyzer) validateCaa(ctx context.Context, subdomain string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCAA)
	msg, _, err := d.client.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return false, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	caaExists := false
	iodefValid := true
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeCAA {
			caaExists = true
			if answer.(*dns.CAA).Tag == "iodef" && iodefValid {
				iodefValid = validateIoDefProperty(answer.(*dns.CAA).Value)
			}
		}
	}

	return caaExists && iodefValid, nil
}

func validateIoDefProperty(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "mailto:") || strings.HasPrefix(value, "https://")
}

func (d domainAnalyzer) caa(ctx context.Context, target Target) (bool, error) {
	subs := getAllSubdomainsFromTarget(target)
	for _, sub := range subs {
		exist, err := d.validateCaa(ctx, sub)
		if err != nil {
			return false, err
		}
		if exist {
			return true, nil
		}
	}
	return false, nil
}

func getAllSubdomainsFromTarget(target Target) []string {
	parts := strings.Split(target.URL.Hostname(), ".")

	subs := make([]string, len(parts)-1)
	for i := 0; i < len(parts)-1; i++ {
		subs[i] = utils.Join(parts[i:], ".")
	}
	return subs
}

func NewDomainAnalyzer() analyzer[any] {
	c := new(dns.Client)
	return &domainAnalyzer{
		client: c,
	}
}

func (d *domainAnalyzer) Analyze(ctx context.Context, target Target, _ any) (map[AnalysisRuleId]AnalysisResult, error) {
	// check if we can use a cached value
	cachedValue, err := target.Options.CachingLayer.Get(ctx, target.URL.Hostname())
	if err == nil {
		cache, err := getFromCache(cachedValue, d.GetAnalysisRuleIds())
		if err == nil {
			return cache, nil
		}
	}

	startTlsDaneChan := concurrency.WrapInChan(
		maybeDoChecksFactory([]AnalysisRuleId{
			STARTTLS,
			DANE,
		}, target.Options, func() map[AnalysisRuleId]AnalysisResult {
			return d.starttlsAndDane(ctx, target)
		},
		))

	res := concurrency.All(
		maybeDoCheckFactory(DKIM, target.Options, func() AnalysisResult {
			return d.dkim(ctx, target)
		}),
		maybeDoCheckFactory(SPF, target.Options, func() AnalysisResult {
			return d.spf(ctx, target)
		}),
		maybeDoCheckFactory(DMARC, target.Options, func() AnalysisResult {
			return d.dmarc(ctx, target)
		}),
		maybeDoCheckFactory(DNSSec, target.Options, func() AnalysisResult {
			start := time.Now()
			didPass := interpret(d.dnssec(ctx, target))
			return NewAnalysisResult(didPass, nil, nil, nil, time.Since(start))
		}),
		maybeDoCheckFactory(CAA, target.Options, func() AnalysisResult {
			start := time.Now()
			didPass := interpret(d.caa(ctx, target))
			return NewAnalysisResult(didPass, nil, nil, nil, time.Since(start))
		}),
	)

	// wait for the starttls and dane check to finish
	startTlsDaneRes := <-startTlsDaneChan

	// dane actually requires DNSSEC to be enabled
	if res[3].DidPass != Success {
		obj := startTlsDaneRes[DANE]
		obj.DidPass = Failure
		obj.Errors = append(startTlsDaneRes[DANE].Errors, DaneMissingStarttls)
		startTlsDaneRes[DANE] = obj
	}

	m := map[AnalysisRuleId]AnalysisResult{
		DKIM:     res[0],
		SPF:      res[1],
		DMARC:    res[2],
		STARTTLS: startTlsDaneRes[STARTTLS],
		DANE:     startTlsDaneRes[DANE],
		DNSSec:   res[3],
		CAA:      res[4],
	}

	// cache the result
	target.Options.CachingLayer.Set(ctx, target.URL.Hostname(), m, 1*time.Hour) // nolint // just swallow the error
	return m, nil
}

func (d *domainAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{DNSSec, CAA, SPF, DKIM, DMARC, STARTTLS, DANE}
}
