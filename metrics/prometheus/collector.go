// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package prometheus

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/metrics"
)

var (
	typeGaugeTpl           = "# TYPE %s gauge\n"
	typeCounterTpl         = "# TYPE %s counter\n"
	typeSummaryTpl         = "# TYPE %s summary\n"
	keyValueTpl            = "%s %v\n\n"
	keyQuantileTagValueTpl = "%s {quantile=\"%s\"} %v\n"
)

// collector is a collection of byte buffers that aggregate Prometheus reports
// for different metric types.
type collector struct {
	buff *bytes.Buffer
}

// newCollector creates a new Prometheus metric aggregator.
func newCollector() *collector {
	return &collector{
		buff: &bytes.Buffer{},
	}
}

func (c *collector) addCounter(name string, m metrics.Counter) {
	c.writeGaugeCounter(name, m.Count())
}

func (c *collector) addGauge(name string, m metrics.Gauge) {
	c.writeGaugeCounter(name, m.Value())
}

func (c *collector) addGaugeFloat64(name string, m metrics.GaugeFloat64) {
	c.writeGaugeCounter(name, m.Value())
}

func (c *collector) addHistogram(name string, m metrics.Histogram) {
	pv := []float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999}
	ps := m.Percentiles(pv)
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	for i := range pv {
		c.writeSummaryPercentile(name, strconv.FormatFloat(pv[i], 'f', -1, 64), ps[i])
	}
	c.writeSummaryCounterAndSum(name, m.Count())
}

func (c *collector) addMeter(name string, m metrics.Meter) {
	c.writeGaugeCounter(name, m.Count())
}

func (c *collector) addTimer(name string, m metrics.Timer) {
	pv := []float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999}
	ps := m.Percentiles(pv)
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	for i := range pv {
		c.writeSummaryPercentile(name, strconv.FormatFloat(pv[i], 'f', -1, 64), ps[i])
	}
	c.writeSummaryCounterAndSum(name, m.Count())
}

func (c *collector) addResettingTimer(name string, m metrics.ResettingTimer) {
	if len(m.Values()) <= 0 {
		return
	}
	ps := m.Percentiles([]float64{50, 95, 99})
	val := m.Values()
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	c.writeSummaryPercentile(name, "0.50", ps[0])
	c.writeSummaryPercentile(name, "0.95", ps[1])
	c.writeSummaryPercentile(name, "0.99", ps[2])
	c.writeSummaryCounterAndSum(name, len(val))
}

func (c *collector) writeGaugeCounter(name string, value interface{}) {
	name = mutateKey(name)
	c.buff.WriteString(fmt.Sprintf(typeGaugeTpl, name))
	c.buff.WriteString(fmt.Sprintf(keyValueTpl, name, value))
}

func (c *collector) writeSummaryCounterAndSum(name string, countValue interface{}) {
	// https://opentelemetry.io/docs/specs/otel/compatibility/prometheus_and_openmetrics/
	// The quantile label on non-suffixed metrics is used to identify quantile points in summary metrics. Each Prometheus line produces one quantile on the resulting summary.
	// Lines with _count and _sum suffixes are used to determine the summary’s count and sum.
	// If _count is not present, the metric MUST be dropped.
	// If _sum is not present, the summary’s sum MUST be set to zero.
	c.writeSummaryCounter(name, countValue)
	c.writeSummarySum(name, 0)
}

func (c *collector) writeSummaryCounter(name string, value interface{}) {
	name = mutateKey(name + "_count")
	c.buff.WriteString(fmt.Sprintf("%s %v\n", name, value))
}

func (c *collector) writeSummarySum(name string, value interface{}) {
	name = mutateKey(name + "_sum")
	c.buff.WriteString(fmt.Sprintf(keyValueTpl, name, value))
}

func (c *collector) writeSummaryPercentile(name, p string, value interface{}) {
	name = mutateKey(name)
	c.buff.WriteString(fmt.Sprintf(keyQuantileTagValueTpl, name, p, value))
}

func mutateKey(key string) string {
	return strings.Replace(key, "/", "_", -1)
}
