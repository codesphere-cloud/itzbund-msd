package scanner

type FnMap[Param any] map[string]func(param Param) bool

type validator[Param any] struct {
	Recommendations FnMap[Param]
	Errors          FnMap[Param]
}

func NewValidator[Param any, Errors string, Recommendations string](errorFnMap, recFnMap FnMap[Param]) validator[Param] {
	return validator[Param]{
		Recommendations: recFnMap,
		Errors:          errorFnMap,
	}
}

func (v validator[Param]) Validate(data Param) (*bool, []string, []string) {
	var didPass bool
	var errors []string
	var recommendations []string

	for t, fn := range v.Errors {
		if fn(data) {
			errors = append(errors, t)
		}
	}

	for t, fn := range v.Recommendations {
		if fn(data) {
			recommendations = append(recommendations, t)
		}
	}

	if len(errors) == 0 {
		didPass = true
	}

	return &didPass, errors, recommendations
}
