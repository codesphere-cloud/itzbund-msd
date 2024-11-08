package scanner

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"

	"golang.org/x/net/html"
)

type languageDetector interface {
	PredictIsEnglish(text string) float64
}
type accessibilityAnalyzer struct {
	languageDetector languageDetector
}

func (a accessibilityAnalyzer) providesEnglishWebsiteVersion(resp httpclient.Response) AnalysisResult {
	start := time.Now()
	// parse the body and look for <script> and <link> tags
	// ref: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	b, err := resp.ResponseBody()
	if err != nil {
		slog.Warn("Failed to get response body", "err", err)
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}

	domDocTest := html.NewTokenizer(bytes.NewReader(b))
	previousStartTokenTest := domDocTest.Token()

	textToIdentify := make([]string, 0)

loopDomTest:
	for {
		tt := domDocTest.Next()
		switch {
		case tt == html.ErrorToken:
			break loopDomTest // End of the document,  done
		case tt == html.StartTagToken:
			previousStartTokenTest = domDocTest.Token()
		case tt == html.TextToken:
			if previousStartTokenTest.Data == "script" || previousStartTokenTest.Data == "link" || previousStartTokenTest.Data == "style" {
				continue
			}
			txtContent := strings.TrimSpace(html.UnescapeString(string(domDocTest.Text())))
			if len(txtContent) > 0 {
				textToIdentify = append(textToIdentify, txtContent)
			}
		}
	}

	if len(textToIdentify) == 0 {
		return NewAnalysisResult(Failure, nil, []string{
			"no_text_to_identify",
		}, nil, time.Since(start))
	}

	propability := a.languageDetector.PredictIsEnglish(strings.Join(textToIdentify, " "))

	return NewAnalysisResult(interpret(propability > 0.9, nil), map[string]any{
		"propability": propability,
	}, nil, nil, time.Since(start))
}

func NewAccessibilityAnalyzer(languageDetector languageDetector) analyzer[httpclient.Response] {
	return accessibilityAnalyzer{
		languageDetector: languageDetector,
	}
}

func (c accessibilityAnalyzer) Analyze(ctx context.Context, target Target, resp httpclient.Response) (map[AnalysisRuleId]AnalysisResult, error) {
	return map[AnalysisRuleId]AnalysisResult{
		ProvidesEnglishWebsiteVersion: maybeDoCheck(ProvidesEnglishWebsiteVersion, target.Options, func() AnalysisResult { return c.providesEnglishWebsiteVersion(resp) }),
	}, nil
}

func (c accessibilityAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{ProvidesEnglishWebsiteVersion}
}
