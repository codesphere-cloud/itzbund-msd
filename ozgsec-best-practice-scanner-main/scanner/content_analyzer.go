package scanner

import (
	"bytes"
	"context"
	"strings"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"golang.org/x/net/html"
)

type contentAnalyzer struct {
}

func subResourceIntegrityAndMixedContent(resp httpclient.Response) (AnalysisResult, AnalysisResult) {
	start := time.Now()
	// parse the body and look for <script> and <link> tags
	// ref: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	b, err := resp.ResponseBody()
	if err != nil {
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start)), NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}

	tkn := html.NewTokenizer(bytes.NewReader(b))

	integrity := true

	noMixedContent := true
	httpSrc := false
	httpsSrc := false

nextEl:
	for {
		t := tkn.Next()
		if t == html.ErrorToken {
			break
		}
		if t == html.StartTagToken {
			tknTag := tkn.Token()
			// check for <script> and <link> tags
			if tknTag.Data == "script" || tknTag.Data == "link" {
				for _, a := range tknTag.Attr {
					if a.Key == "integrity" {
						// found an integrity attribute
						if !noMixedContent {
							// we already found a source which has mixed content
							// we can stop looking
							continue nextEl
						}
					}
					// check if the source is http
					if a.Key == "src" || a.Key == "href" {
						if strings.HasPrefix(a.Val, "http://") {
							httpSrc = true
						} else {
							httpsSrc = true
						}
						if httpsSrc && httpSrc {
							// found a source which has mixed content
							noMixedContent = false
							if !integrity {
								// we already found a source without integrity
								// we can stop looking
								continue nextEl
							}
						}
					}
				}
				// no integrity attribute found
				integrity = false
			}
			if tknTag.Data == "img" || tknTag.Data == "iframe" {
				for _, a := range tknTag.Attr {
					// check if the source is http
					if a.Key == "src" {
						if strings.HasPrefix(a.Val, "http://") {
							httpSrc = true
						} else {
							httpsSrc = true
						}
						if httpSrc && httpsSrc {
							// found a source which has mixed content
							noMixedContent = false
							if !integrity {
								// we already found a source without integrity
								// we can stop looking
								continue nextEl
							}
						}
					}
				}
			}
		}
	}
	return NewAnalysisResult(ptr(integrity), nil, nil, nil, time.Since(start)), NewAnalysisResult(ptr(noMixedContent), nil, nil, nil, time.Since(start))
}

func NewContentAnalyzer() analyzer[httpclient.Response] {
	return contentAnalyzer{}
}

func (c contentAnalyzer) Analyze(ctx context.Context, target Target, resp httpclient.Response) (map[AnalysisRuleId]AnalysisResult, error) {
	if !doingAnyChecks(target.Options, c.GetAnalysisRuleIds()) {
		return nil, nil
	}
	// if we are doing either mixed content or subresource integrity, we need to parse the body - so we do both at the same time
	subresourceIntegrity, noMixedContent := subResourceIntegrityAndMixedContent(resp)

	return map[AnalysisRuleId]AnalysisResult{
		SubResourceIntegrity: subresourceIntegrity,
		NoMixedContent:       noMixedContent,
	}, nil
}

func (c contentAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{SubResourceIntegrity, NoMixedContent}
}
