package monitoring

import (
	"go.opentelemetry.io/otel/sdk/metric"
)

type Monitorable interface {
	Fields() map[string]interface{}
	Tags() map[string]string
	Measurement() string
	Points() []Monitorable

	WritePrometheus(meter *metric.MeterProvider) error
}

type Point struct {
	PointMeasurement string
	PointTags        map[string]string
	PointFields      map[string]interface{}
}

func (p Point) Fields() map[string]interface{} {
	return p.PointFields
}

func (p Point) Tags() map[string]string {
	return p.PointTags
}

func (p Point) Measurement() string {
	return p.PointMeasurement
}

func (p Point) Points() []Monitorable {
	return []Monitorable{}
}
