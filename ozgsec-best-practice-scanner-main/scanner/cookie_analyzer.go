package scanner

import (
	"context"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

type cookieAnalyzer struct {
}

func secureSessionCookies(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	cookies := resp.Response().Cookies()
	for _, c := range cookies {
		// determine which cookie is a session cookie...
		// ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes
		if c.Expires.IsZero() {
			// its not a session cookie
			continue
		}
		if !c.Secure || !c.HttpOnly {
			return NewAnalysisResult(Failure, map[string]string{
				"cookie": c.String(),
			}, nil, nil, time.Since(start))
		}
	}
	return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
}

func (c cookieAnalyzer) Analyze(ctx context.Context, target Target, resp httpclient.Response) (map[AnalysisRuleId]AnalysisResult, error) {
	return map[AnalysisRuleId]AnalysisResult{
		SecureSessionCookies: maybeDoCheck(SecureSessionCookies, target.Options, func() AnalysisResult { return secureSessionCookies(resp) }),
	}, nil
}

func (c cookieAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		SecureSessionCookies,
	}
}

func NewCookieAnalyzer() analyzer[httpclient.Response] {
	return &cookieAnalyzer{}
}
