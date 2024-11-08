package language

import "github.com/pemistahl/lingua-go"

type languageDetector struct {
	detector lingua.LanguageDetector
}

func NewLanguageDetector() languageDetector {
	detector := lingua.NewLanguageDetectorBuilder().
		FromLanguages(
			lingua.German,
			lingua.English,
		).WithPreloadedLanguageModels().
		Build()
	return languageDetector{detector: detector}
}

func (l languageDetector) PredictIsEnglish(text string) float64 {
	return l.detector.ComputeLanguageConfidence(text, lingua.English)
}
