package monitoring

import (
	"time"

	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
)

func newTraceProvider() (*trace.TracerProvider, error) {
	traceExporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			trace.WithBatchTimeout(time.Second)),
	)
	return traceProvider, nil
}

func newMeterProvider(exporter metric.Reader) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(exporter),
	)
	return meterProvider, nil
}

func newLoggerProvider() (*log.LoggerProvider, error) {
	logExporter, err := stdoutlog.New()
	if err != nil {
		return nil, err
	}

	loggerProvider := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
	)
	return loggerProvider, nil
}

type otelMonitor struct {
	meterProvider  *metric.MeterProvider
	tracerProvider *trace.TracerProvider
	loggerProvider *log.LoggerProvider
}

func NewOTELMonitor(metricsExporter metric.Reader) *otelMonitor {
	meterProvider, err := newMeterProvider(metricsExporter)
	if err != nil {
		panic(err)
	}

	loggerProvider, err := newLoggerProvider()
	if err != nil {
		panic(err)
	}

	tracerProvider, err := newTraceProvider()
	if err != nil {
		panic(err)
	}

	return &otelMonitor{
		meterProvider:  meterProvider,
		tracerProvider: tracerProvider,
		loggerProvider: loggerProvider,
	}
}

func (o *otelMonitor) Write(m Monitorable) error {
	err := m.WritePrometheus(o.meterProvider)
	if err != nil {
		return err
	}
	points := m.Points()
	for _, p := range points {
		if err := p.WritePrometheus(o.meterProvider); err != nil {
			return err
		}
	}
	return nil
}

func NewPromExporter() (metric.Reader, error) {
	return prometheus.New()
}
