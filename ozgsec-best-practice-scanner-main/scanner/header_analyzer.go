package scanner

import (
	"context"
	"strings"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

type headerAnalyzer struct {
	hstsValidator                  validator[string]
	xFrameOptionsValidator         validator[string]
	xssProtectionValidator         validator[string]
	hstsPreloadedValidator         validator[string]
	xContentTypeOptionsValidator   validator[string]
	contentSecurityPolicyValidator validator[string]
}

const (
	MissingHeader             = "missingHeader"
	MissingMaxAge             = "missingMaxAge"
	MissingIncludeSubDomains  = "missingIncludeSubDomains"
	MissingModeBlock          = "missingModeBlock"
	MissingDefaultSrcWithSelf = "missingDefaultSrcWithSelf"
	MissingScriptSrc          = "missingScriptSrc"
	MissingStyleSrc           = "missingStyleSrc"
	MissingImgSrc             = "missingImgSrc"
	NotEnabled                = "notEnabled"
	NotDenyOrSameOrigin       = "notDenyOrSameOrigin"
	MissingPreload            = "missingPreload"
	MaxAgeTooLow              = "maxAgeTooLow"
	NotNoSniff                = "notNoSniff"
)

func newHstsValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingHeader: func(val string) bool {
			return val == ""
		},
		MissingMaxAge: func(val string) bool {
			return !strings.Contains(val, "max-age")
		}},
		FnMap[string]{
			MissingIncludeSubDomains: func(val string) bool {
				return !strings.Contains(val, "includeSubDomains")
			},
		})
}

func newXFrameOptionsValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingHeader: func(val string) bool {
			return val == ""
		},
		NotDenyOrSameOrigin: func(val string) bool {
			return strings.ToUpper(val) != "DENY" && strings.ToUpper(val) != "SAMEORIGIN"
		},
	}, FnMap[string]{})
}

func newXSSProtectionValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingHeader: func(val string) bool {
			return val == ""
		},
		NotEnabled: func(val string) bool {
			return !strings.Contains(val, "1")
		},
		MissingModeBlock: func(val string) bool {
			return !strings.Contains(val, "mode=block")
		},
	}, FnMap[string]{})
}

func newXContentTypeOptionsValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingHeader: func(val string) bool {
			return val == ""
		},
		NotNoSniff: func(val string) bool {
			return val != "nosniff"
		},
	}, FnMap[string]{})
}

func newContentSecurityPolicyValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingHeader: func(val string) bool {
			return val == ""
		},
	}, FnMap[string]{
		MissingDefaultSrcWithSelf: func(val string) bool {
			return !strings.Contains(val, "default-src 'self'")
		},
		MissingScriptSrc: func(val string) bool {
			return !strings.Contains(val, "script-src")
		},
		MissingStyleSrc: func(val string) bool {
			return !strings.Contains(val, "style-src")
		},
		MissingImgSrc: func(val string) bool {
			return !strings.Contains(val, "img-src")
		},
	})
}

func newHstsPreloadedValidator() validator[string] {
	return NewValidator(FnMap[string]{
		MissingPreload: func(val string) bool {
			return !strings.Contains(val, "preload")
		},
	}, FnMap[string]{})
}

func NewHeaderAnalyzer() analyzer[httpclient.Response] {
	return headerAnalyzer{
		hstsValidator:                  newHstsValidator(),
		xFrameOptionsValidator:         newXFrameOptionsValidator(),
		xssProtectionValidator:         newXSSProtectionValidator(),
		hstsPreloadedValidator:         newHstsPreloadedValidator(),
		xContentTypeOptionsValidator:   newXContentTypeOptionsValidator(),
		contentSecurityPolicyValidator: newContentSecurityPolicyValidator(),
	}
}

func (i headerAnalyzer) hsts(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("Strict-Transport-Security")
	didPass, errors, recommendations := i.hstsValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"Strict-Transport-Security": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) xFrameOptions(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("X-Frame-Options")
	didPass, errors, recommendations := i.xFrameOptionsValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"X-Frame-Options": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) xssProtection(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("X-XSS-Protection")
	didPass, errors, recommendations := i.xssProtectionValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"X-XSS-Protection": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) hstsPreloaded(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("Strict-Transport-Security")
	didPass, errors, recommendations := i.hstsPreloadedValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"Strict-Transport-Security": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) xContentTypeOptions(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("X-Content-Type-Options")
	didPass, errors, recommendations := i.xContentTypeOptionsValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"X-Content-Type-Options": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) contentSecurityPolicy(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	header := resp.Response().Header.Get("Content-Security-Policy")
	didPass, errors, recommendations := i.contentSecurityPolicyValidator.Validate(header)

	return NewAnalysisResult(didPass, map[string]any{
		"Content-Security-Policy": header,
	}, errors, recommendations, time.Since(start))
}

func (i headerAnalyzer) Analyze(ctx context.Context, target Target, resp httpclient.Response) (map[AnalysisRuleId]AnalysisResult, error) {
	return map[AnalysisRuleId]AnalysisResult{
		HTTPS: maybeDoCheck(HTTPS, target.Options, func() AnalysisResult {
			return NewAnalysisResult(ptr(resp.Response().Request.URL.Scheme == "https"), nil, nil, nil, time.Duration(0))
		}),
		HSTS:                  maybeDoCheck(HSTS, target.Options, func() AnalysisResult { return i.hsts(resp) }),
		XFrameOptions:         maybeDoCheck(XFrameOptions, target.Options, func() AnalysisResult { return i.xFrameOptions(resp) }),
		XSSProtection:         maybeDoCheck(XSSProtection, target.Options, func() AnalysisResult { return i.xssProtection(resp) }),
		HSTSPreloaded:         maybeDoCheck(HSTSPreloaded, target.Options, func() AnalysisResult { return i.hstsPreloaded(resp) }),
		ContentTypeOptions:    maybeDoCheck(ContentTypeOptions, target.Options, func() AnalysisResult { return i.xContentTypeOptions(resp) }),
		ContentSecurityPolicy: maybeDoCheck(ContentSecurityPolicy, target.Options, func() AnalysisResult { return i.contentSecurityPolicy(resp) }),
	}, nil
}

func (i headerAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		HTTPS,
		HSTS,
		XFrameOptions,
		XSSProtection,
		HSTSPreloaded,
		ContentTypeOptions,
		ContentSecurityPolicy,
	}
}
