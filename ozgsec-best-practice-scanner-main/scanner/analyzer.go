package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/monitoring"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

// analyzing happens in a tree-like structure
// the last provided parameter is some values which were gathered along the way and can be used for child analysis. For example an tls connection was established in the parent analysis and is used inside the child analyzes to inspect the certificate
// nevertheless each analysis is independent and can be used on its own
type analyzer[ParentContext any] interface {
	GetAnalysisRuleIds() []AnalysisRuleId
	Analyze(ctx context.Context, target Target, parentContext ParentContext) (map[AnalysisRuleId]AnalysisResult, error) // it performs one to infinite many analyzes
}

type AnalyzerGroup[ParentContext any] struct {
	analyzers []analyzer[ParentContext]
	cache     map[AnalysisRuleId]AnalysisResult
	mut       *sync.Mutex
}

func NewAnalyzerGroup[ParentContext any](analyzers ...analyzer[ParentContext]) AnalyzerGroup[ParentContext] {
	return AnalyzerGroup[ParentContext]{
		analyzers: analyzers,
		cache:     make(map[AnalysisRuleId]AnalysisResult), // just an empty map - will be filled if fetch and respect cache is called.
		mut:       &sync.Mutex{},
	}
}

// Analyze runs all analyzers and returns the results
// if one analyzer returns an error, the error is logged and the analysis continues
// the results are merged into one map
// the parentContext is passed to each analyzer
// this function can never return an error
func (a AnalyzerGroup[ParentContext]) Analyze(ctx context.Context, target Target, parentContext ParentContext) (map[AnalysisRuleId]AnalysisResult, error) {
	var res = make(map[AnalysisRuleId]AnalysisResult)
	wg := sync.WaitGroup{}

	for _, childAnalyzer := range a.analyzers {
		// run all analyzers and collect the results
		// run them in parallel
		wg.Add(1)
		go func(analyzer analyzer[ParentContext]) {
			// do not use the provided context as parent
			// we are looking for bugs in the analyzer which might not react correctly to a canceled context
			// instead we use a new context and cancel it after the analysis is done
			measurementCtx, cancel := context.WithCancel(context.Background())

			defer func() {
				if r := recover(); r != nil {
					// cancel the measurment context
					cancel()
					// if a panic happens, we just build an error and continue
					// but we log the panic so we can fix it
					stack := debug.Stack()
					if err := monitoring.SendSlackWebhookAlert("panic in analyzer: " + string(stack)); err != nil {
						slog.Error("SLACK_WEBHOOK is not set - cannot send slack webhook alert")
					}
					fmt.Println("panic in analyzer: ", string(r.(error).Error()), string(stack))
					res = utils.Merge(res, buildAnalysisError(r, analyzer.GetAnalysisRuleIds()))
				}
			}()

			defer wg.Done()

			// measure the time it takes to run the analysis
			start := time.Now()
			defer func() {
				if time.Since(start) > 15*time.Second {
					slog.Warn("analyzer finished", "analyzer", a.GetAnalysisRuleIds(), "duration", time.Since(start).Milliseconds())
				}
			}()

			go func() {
				select {
				case <-measurementCtx.Done():
					return
				case <-time.After(15 * time.Second):
					slog.Warn("analyzer running for more than 15 seconds", "analyzer", a.GetAnalysisRuleIds(), "duration", time.Since(start).Milliseconds())
				}
			}()

			analysisResultMap, err := analyzer.Analyze(ctx, target, parentContext)
			cancel()
			if err != nil {
				slog.Error("analyzer returned error", "err", err)
				// build the inspection error - this way a analyzerGroup can never return an error - it will always return a result
				analysisResultMap = buildAnalysisError(err, analyzer.GetAnalysisRuleIds())

				a.mut.Lock()
				res = utils.Merge(res, analysisResultMap)
				a.mut.Unlock()
				return
			}
			a.mut.Lock()
			res = utils.Merge(res, analysisResultMap)
			a.mut.Unlock()
		}(childAnalyzer)
	}
	wg.Wait()
	return res, nil
}

func (a AnalyzerGroup[ParentContext]) GetAnalysisRuleIds() []AnalysisRuleId {
	var res = make([]AnalysisRuleId, 0)
	for _, a := range a.analyzers {
		res = append(res, a.GetAnalysisRuleIds()...)
	}
	return res
}
