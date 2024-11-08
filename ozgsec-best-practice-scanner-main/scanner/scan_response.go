package scanner

import (
	"context"
	"encoding/json"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/monitoring"
	"go.opentelemetry.io/otel/sdk/metric"
)

type ScanResponse struct {
	Target    string `json:"target"`
	SUT       string `json:"sut"`
	IpAddress string `json:"ipAddress"`
	Duration  int64  `json:"duration"`
	Timestamp int64  `json:"timestamp"`
	Result    any    `json:"result"`
	// the ip address of the scanner
	// which was used to scan the target
	ScannerIP string `json:"scannerIP"`
}

func (s ScanResponse) Fields() map[string]interface{} {
	if s.IsError() {
		return map[string]interface{}{
			"error": s.ErrorCodeDescription(),
			"uri":   s.Target,
			"sut":   s.SUT,
		}
	}
	return map[string]interface{}{
		"duration": s.Duration,
		"result":   s.Result,
		"uri":      s.Target,
		"sut":      s.SUT,
	}
}

func (s ScanResponse) Tags() map[string]string {
	if s.IsError() {
		return map[string]string{
			"state":     "failure",
			"error":     s.ErrorCodeDescription(),
			"scannerIP": s.ScannerIP,
		}
	}
	return map[string]string{
		"state":     "success",
		"scannerIP": s.ScannerIP,
	}
}

func (s ScanResponse) Measurement() string {
	return "scan"
}

func (s ScanResponse) WritePrometheus(meterProvider *metric.MeterProvider) error {
	// save the scan in a global counter
	meter := meterProvider.Meter("scan")
	counter, err := meter.Int64Counter("scan")
	if err != nil {
		return err
	}

	counter.Add(context.TODO(), 1)

	// save the state
	if s.IsError() {
		counter, err = meter.Int64Counter("failure")
	} else {
		counter, err = meter.Int64Counter("success")
	}
	if err != nil {
		return err
	}

	counter.Add(context.TODO(), 1)

	if !s.IsError() {
		// save the duration
		histogram, err := meter.Int64Histogram("duration")
		if err != nil {
			return err
		}
		histogram.Record(context.TODO(), s.Duration)
	}
	return nil
}

type scanResponsePoint struct {
	monitoring.Point
}

func (s ScanResponse) Points() []monitoring.Monitorable {
	p := []monitoring.Monitorable{}
	for _, unscannable := range s.UnscannableKeys() {
		p = append(p, scanResponsePoint{
			Point: monitoring.Point{
				PointMeasurement: "scan",
				PointTags: map[string]string{
					"state":          "unscannable",
					"inspectionType": string(unscannable),
				},
				PointFields: map[string]interface{}{
					"uri":            s.Target,
					"inspectionType": unscannable,
				}},
		})
	}
	return p
}

// a scanResponsePoint does basically only contain information about what wasn't possible to scan
// simplest is to just put them inside a counter
func (s scanResponsePoint) WritePrometheus(meterProvider *metric.MeterProvider) error {
	meter := meterProvider.Meter("unscannable")
	counter, err := meter.Int64Counter("unscannable_" + s.PointTags["inspectionType"])
	if err != nil {
		return err
	}

	counter.Add(context.TODO(), 1)
	return nil
}

func (s ScanResponse) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s ScanResponse) IsSuccess() bool {
	switch s.Result.(type) {
	case ScanSuccess:
		return true
	default:
		return false
	}
}

func (s ScanResponse) ScanSuccess() ScanSuccess {
	return s.Result.(ScanSuccess)
}

func (s ScanResponse) ErrorCodeDescription() string {
	switch s.Result.(type) {
	case ScanError:
		return s.Result.(ScanError).Error.ErrorCodeDescription
	default:
		return ""
	}
}

func (s ScanResponse) ErrorCode() int {
	switch s.Result.(type) {
	case ScanError:
		return s.Result.(ScanError).Error.Code
	default:
		return 0
	}
}

func (s ScanResponse) IsError() bool {
	return !s.IsSuccess()
}

func (s ScanResponse) UnscannableKeys() []AnalysisRuleId {
	switch r := s.Result.(type) {
	case ScanError:
		return []AnalysisRuleId{}
	case ScanSuccess:
		var unscannable []AnalysisRuleId
		for key, result := range r {
			if result.IsUnknown() {
				unscannable = append(unscannable, key)
			}
		}
		return unscannable
	default:
		return []AnalysisRuleId{}
	}
}
