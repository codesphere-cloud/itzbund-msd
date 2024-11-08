package scanner

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/url"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/concurrency"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/language"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

func selectIPV4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return nil
}

type scanner struct {
	httpAnalyzers analyzer[httpclient.Response]
	netAnalyzers  analyzer[any]
	tlsAnalyzers  analyzer[*tls.ConnectionState]
}

func NewScanner() scanner {
	languageDetector := language.NewLanguageDetector()
	// init all scanners
	var certificateAnalyzer = NewCertificateAnalyzer()
	var contentAnalyzer = NewContentAnalyzer()
	var cookieAnalyzer = NewCookieAnalyzer()
	var domainAnalyzer = NewDomainAnalyzer()
	var headerAnalyzer = NewHeaderAnalyzer()
	var networkAnalyzer = NewNetworkAnalyzer(httpclient.NewDefaultClient())
	var organizationalAnalyzer = NewOrgAnalyzer()
	var tlsAnalyzer = NewTLSAnalyzer()
	var httpAnalyzer = NewHttpAnalyzer()
	var accessibilityAnalyzer = NewAccessibilityAnalyzer(languageDetector)

	httpAnalyzers := NewAnalyzerGroup(
		contentAnalyzer,
		cookieAnalyzer,
		headerAnalyzer,
		httpAnalyzer,
		accessibilityAnalyzer,
	)
	netAnalyzers := NewAnalyzerGroup(
		organizationalAnalyzer,
		domainAnalyzer,
		networkAnalyzer,
	)
	tlsAnalyzers := NewAnalyzerGroup(
		certificateAnalyzer,
		tlsAnalyzer,
	)

	return scanner{
		httpAnalyzers: httpAnalyzers,
		netAnalyzers:  netAnalyzers,
		tlsAnalyzers:  tlsAnalyzers,
	}
}

type ScanSuccess = map[AnalysisRuleId]AnalysisResult

type tlsClient interface {
	Get(ctx context.Context, target *url.URL, tlsConfig *tls.Config) (net.Conn, error)
}
type httpClient interface {
	Get(ctx context.Context, target *url.URL) (resp httpclient.Response, err error)
}

type cacher[T any] interface {
	// Get returns the value for the given key.
	Get(ctx context.Context, key string) (T, error)
	// Set sets the value for the given key.
	Set(ctx context.Context, key string, value T, expires time.Duration) error
	// Delete deletes the value for the given key.
	Delete(ctx context.Context, key string) error
}

type TargetScanOptions struct {
	CachingLayer  cacher[any]
	HttpClient    httpClient
	TlsClient     tlsClient
	EnabledChecks map[AnalysisRuleId]bool // provides a map, which checks should be executed
}

func maybeDoCheck(check AnalysisRuleId, options TargetScanOptions, fn func() AnalysisResult) AnalysisResult {
	if enabled := options.EnabledChecks[check]; enabled {
		return fn()
	}
	return NewAnalysisResult(Unknown, nil, nil, nil, 0)
}

func maybeDoCheckFactory(check AnalysisRuleId, options TargetScanOptions, fn func() AnalysisResult) func() AnalysisResult {
	return func() AnalysisResult {
		return maybeDoCheck(check, options, fn)
	}
}

func maybeDoChecks(checks []AnalysisRuleId, options TargetScanOptions, fn func() map[AnalysisRuleId]AnalysisResult) map[AnalysisRuleId]AnalysisResult {
	if doingAnyChecks(options, checks) {
		return fn()
	}
	res := make(map[AnalysisRuleId]AnalysisResult)
	for _, check := range checks {
		res[check] = NewAnalysisResult(Unknown, nil, nil, nil, 0)
	}
	return res
}

func maybeDoChecksFactory(checks []AnalysisRuleId, options TargetScanOptions, fn func() map[AnalysisRuleId]AnalysisResult) func() map[AnalysisRuleId]AnalysisResult {
	return func() map[AnalysisRuleId]AnalysisResult {
		return maybeDoChecks(checks, options, fn)
	}
}

func doingAnyChecks(options TargetScanOptions, checks []AnalysisRuleId) bool {
	for _, check := range checks {
		if options.EnabledChecks[check] {
			return true
		}
	}
	return false
}

type Target struct {
	URL         *url.URL
	IPV4Address net.IP            // selected IP Address to test against
	IPs         []net.IP          // all IP Addresses of that domain - only necessary for a few inspections
	Options     TargetScanOptions // allows to pass options to the scan - this can be used for flow control and caching - it avoids the need to pass around a lot of parameters
}

func NewTarget(url *url.URL, ips []net.IP, options TargetScanOptions) Target {
	return Target{
		URL:         url,
		IPs:         ips,
		IPV4Address: selectIPV4(ips),
		Options:     options,
	}
}

func (t Target) SupportsIPV6() bool {
	for _, ip := range t.IPs {
		if ip.To4() == nil {
			return true
		}
	}
	return false
}

type ScanError struct {
	Error struct {
		Code                 int
		ErrorCodeDescription string
	}
}

func NewScanError(code int, codeDescription string) ScanError {
	return ScanError{
		Error: struct {
			Code                 int
			ErrorCodeDescription string
		}{
			Code:                 code,
			ErrorCodeDescription: codeDescription,
		},
	}
}

type resp struct {
	resp httpclient.Response
	err  error
}

var ipApiURL, _ = url.Parse("https://ipinfo.io/ip")

var resolver *net.Resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Millisecond * time.Duration(10000),
		}
		// use google dns to resolve the ip
		// there might be issues depending on the deployment environment
		return d.DialContext(ctx, network, "8.8.8.8:53")
	},
}

func (s scanner) Scan(ctx context.Context, targetURI string, options TargetScanOptions) ScanResponse {
	start := time.Now()
	// overwrite the options and provide a batching cache instead of the provided one.
	// the batching cache will be flushed after the scan is finished
	// otherwise the analyzers might overwrite each others values during the scan.
	batchCache := cache.NewBatchCache(options.CachingLayer)
	options.CachingLayer = batchCache
	// flush the batching cache after all analyzers are finished
	defer func() {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		batchCache.Flush(cacheCtx)
		cancel()
	}()

	// start with an http request - the http client will follow redirects
	uri, err := url.Parse("http://" + targetURI)
	if err != nil {
		slog.Warn("could not parse url", "err", err, "url", "https://"+targetURI)
		return ScanResponse{
			Target:    targetURI,
			SUT:       targetURI,
			IpAddress: "",
			Duration:  0,
			Timestamp: time.Now().UnixMilli(),
			Result:    NewScanError(1, "could_not_parse_url"),
		}
	}

	// do a simple http request to check what URL we are actually looking at
	callResults := concurrency.All[any](
		func() any {
			r, err := options.HttpClient.Get(ctx, uri)
			return resp{resp: r, err: err}
		},
		func() any {
			// call an http api to get the ip address of the scanner
			res, err := options.HttpClient.Get(ctx, ipApiURL)
			if err != nil {
				slog.Warn("could not get scanner ip", "err", err)
				return ""
			}
			ip, err := res.ResponseBody()
			if err != nil {
				slog.Warn("could not get scanner ip", "err", err)
				return ""
			}
			return string(ip)
		},
	)

	resp, err := callResults[0].(resp).resp, callResults[0].(resp).err
	scannerIP := callResults[1].(string)

	if err != nil {
		slog.Error("could not get response, skipping http analyzers", "err", err)
		// we were not able to resolve the URL
		// build up the target object using the provided value only
		ips, err := resolver.LookupIP(ctx, "ip", uri.Hostname())
		if err != nil {
			// we were not able to resolve the hostname
			return ScanResponse{
				Target:    targetURI,
				SUT:       targetURI,
				IpAddress: "",
				Duration:  0,
				Timestamp: time.Now().UnixMilli(),
				Result:    NewScanError(2, "could_not_resolve_hostname"),
				ScannerIP: scannerIP,
			}
		}

		// check if the ctx did timeout
		if ctx.Err() == context.DeadlineExceeded {
			// allow an additional 5 seconds for the other scanners to finish
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}

		target := Target{URL: uri, IPs: ips, IPV4Address: selectIPV4(ips), Options: options}

		analysisResult := concurrency.All(
			func() map[AnalysisRuleId]AnalysisResult {
				// just return an error for the http analysis
				return buildAnalysisError(err, s.httpAnalyzers.GetAnalysisRuleIds())
			},
			func() map[AnalysisRuleId]AnalysisResult {
				// we cannot provide a tls connection state
				res, _ := s.tlsAnalyzers.Analyze(ctx, target, nil)
				return res
			},
			func() map[AnalysisRuleId]AnalysisResult {
				res, _ := s.netAnalyzers.Analyze(ctx, target, nil)
				return res
			},
		)

		res := utils.Merge(analysisResult...)
		printTiming(target.Options, res)
		return ScanResponse{
			Target:    targetURI,
			SUT:       targetURI,
			IpAddress: target.IPV4Address.String(),
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UnixMilli(),
			Result:    res,
			ScannerIP: scannerIP,
		}
	}

	sut := resp.GetURL().String()

	// remove the scheme from the sut
	sut = sut[len(resp.GetURL().Scheme)+3:]
	// build the target object
	// do an ip lookup
	ips, err := net.LookupIP(resp.GetURL().Hostname())
	if err != nil {
		// we were not able to resolve the URL
		// build up the target object using the provided value only
		return ScanResponse{
			Target:    targetURI,
			SUT:       sut,
			IpAddress: "",
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UnixMilli(),
			Result:    NewScanError(2, "could_not_resolve_hostname"),
		}
	}
	target := Target{URL: resp.GetURL(), IPs: ips, IPV4Address: selectIPV4(ips), Options: options}

	analysisResult := concurrency.All(
		func() map[AnalysisRuleId]AnalysisResult {
			// just return an error for the http analysis
			res, _ := s.httpAnalyzers.Analyze(ctx, target, resp)
			return res
		},
		func() map[AnalysisRuleId]AnalysisResult {
			// we cannot provide a tls connection state
			res, _ := s.tlsAnalyzers.Analyze(ctx, target, resp.TLS())
			return res
		},
		func() map[AnalysisRuleId]AnalysisResult {
			res, _ := s.netAnalyzers.Analyze(ctx, target, nil)
			return res
		},
	)

	res := utils.Merge(analysisResult...)
	printTiming(target.Options, res)
	response := ScanResponse{
		Target:    targetURI,
		SUT:       sut,
		IpAddress: target.IPV4Address.String(),
		Duration:  time.Since(start).Milliseconds(),
		Timestamp: time.Now().UnixMilli(),
		Result:    res,
		ScannerIP: scannerIP,
	}

	return response
}

func printTiming(options TargetScanOptions, result map[AnalysisRuleId]AnalysisResult) {
	// extract key and millisecond duration
	timings := make([]any, len(options.EnabledChecks)*2)
	i := 0
	for key, value := range result {
		if !options.EnabledChecks[key] {
			continue
		}

		timings[i] = string(key)
		timings[i+1] = value.Duration
		i += 2
	}

	// sort the timing from longest to shortest
	for i := 0; i < len(timings); i += 2 {
		for j := i + 2; j < len(timings); j += 2 {
			if timings[i+1].(time.Duration) < timings[j+1].(time.Duration) {
				timings[i], timings[j] = timings[j], timings[i]
				timings[i+1], timings[j+1] = timings[j+1], timings[i+1]
			}
		}
	}

	slog.Debug("scan timings", timings...)
}
