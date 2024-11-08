package scanner

import "time"

func errorMessage(err any) string {
	switch e := err.(type) {
	case string:
		return e
	case error:
		return e.Error()
	default:
		return "Unknown error"
	}
}

func buildAnalysisError(err any, rules []AnalysisRuleId) map[AnalysisRuleId]AnalysisResult {
	m := make(map[AnalysisRuleId]AnalysisResult)
	actualVal := make(map[string]any)
	actualVal["error"] = errorMessage(err)
	for _, t := range rules {
		m[t] = NewAnalysisResult(Unknown, actualVal, nil, nil, time.Duration(0))
	}
	return m
}
