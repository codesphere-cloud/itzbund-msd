package scanner

import (
	"context"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

type httpAnalyzer struct {
}

func NewHttpAnalyzer() analyzer[httpclient.Response] {
	return httpAnalyzer{}
}

/*
IMMEDIATE ACTION REQUIRED CHECK
(if a REQUIRED spec is not met, the call to immediate action MUST be shown to the user)

REQUIRED: The tested server responds the HTTP-GET request with a 308 (Permanent Redirect) status code

	(Note from RFC 7538: "This status code is similar to 301 (Moved Permanently), except that it does not allow changing the request method from POST to GET.").

REQUIRED: The target of the redirect is a HTTPS target.
*/
func (i httpAnalyzer) Analyze(ctx context.Context, target Target, resp httpclient.Response) (map[AnalysisRuleId]AnalysisResult, error) {
	httpRedirectsToHttps := resp.Response().TLS != nil && resp.Response().TLS.HandshakeComplete
	return map[AnalysisRuleId]AnalysisResult{
		HTTP: maybeDoCheck(HTTP, target.Options, func() AnalysisResult {
			return NewAnalysisResult(ptr(resp.Response().StatusCode < 500), nil, nil, nil, time.Duration(0))
		}),
		HTTP308: maybeDoCheck(HTTP308, target.Options, func() AnalysisResult {
			return NewAnalysisResult(ptr(httpRedirectsToHttps && resp.InitialResponse().StatusCode == 308), nil, nil, nil, time.Duration(0))
		}),
		HTTPRedirectsToHttps: maybeDoCheck(HTTPRedirectsToHttps, target.Options, func() AnalysisResult {
			return NewAnalysisResult(ptr(httpRedirectsToHttps), nil, nil, nil, time.Duration(0))
		}),
	}, nil
}

func (i httpAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		HTTP,
		HTTP308,
		HTTPRedirectsToHttps,
	}
}
