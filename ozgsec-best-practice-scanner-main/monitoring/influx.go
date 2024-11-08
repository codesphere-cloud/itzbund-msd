package monitoring

import (
	"context"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/pkg/errors"
)

type infux struct {
	writeApi api.WriteAPIBlocking
}

func (i *infux) Write(m Monitorable) error {
	p := influxdb2.NewPointWithMeasurement(m.Measurement())
	for k, v := range m.Tags() {
		p.AddTag(k, v)
	}
	for k, v := range m.Fields() {
		p.AddField(k, v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := i.writeApi.WritePoint(ctx, p)
	if err != nil {
		return errors.Wrap(err, "could not write point to influx")
	}

	subs := m.Points()
	for _, sub := range subs {
		if err := i.Write(sub); err != nil {
			return err
		}
	}
	return nil
}

func NewInflux(url, token, org, bucket string) *infux {
	client := influxdb2.NewClient(url, token)
	return &infux{writeApi: client.WriteAPIBlocking(org, bucket)}
}
