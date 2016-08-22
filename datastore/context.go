// Copyright 2014 The Serviced Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datastore

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	gometrics "github.com/rcrowley/go-metrics"
)

// Context is the context of the application or request being made
type Context interface {
	// Get a connection to the datastore
	Connection() (Connection, error)

	// Get the Metrics object from the context
	Metrics() *Metrics
}

//Register a driver to use for the context
func Register(driver Driver) {
	ctx = newCtx(driver)
}

//Get returns the global Context
func Get() Context {
	return ctx
}

var ctx Context

//new Creates a new context with a Driver to a datastore
func newCtx(driver Driver) Context {
	return &context{driver, newMetrics()}
}

type context struct {
	driver  Driver
	metrics Metrics
}

func (c *context) Connection() (Connection, error) {
	return c.driver.GetConnection()
}

func (c *context) Metrics() *Metrics {
	return &c.metrics
}

/*
 * To record metrics, call: defer ctx.Metrics().Stop(ctx.Metrics().Start("main2"))
 * where you want to time some code through the end of the method. If you want
 * to time portions of the code you can break it out into two calls. Call the Log()
 * method to capture the timing information and clear the data.  For running logs
 * use the go-metrics Log() method, passing in the Metrics.Registy object.
 */
type Metrics struct {
	Enabled  bool
	Registry gometrics.Registry
	Timers   map[string]gometrics.Timer
}

func newMetrics() Metrics {
	return Metrics{
		Registry: gometrics.NewRegistry(), // Keep these metrics separate from others in the app
		Timers:   make(map[string]gometrics.Timer),
	}
}

// Returns a new timing object.  This will be used as an
// argument to Stop() to record the duration/count.
func (m *Metrics) Start(name string) (gometrics.Timer, time.Time) {
	if !m.Enabled {
		return nil, time.Now()
	}
	timer, found := m.Timers[name]
	if !found {
		timer = gometrics.NewTimer()
		m.Timers[name] = timer
		m.Registry.Register(name, timer)
	}
	return timer, time.Now()
}

// When stop is called, calculate the duration.
func (m *Metrics) Stop(timer gometrics.Timer, t time.Time) {
	if timer != nil {
		timer.UpdateSince(t)
	}
}

// Pads the value with units to a given width.
// padUnits(14, 0.22, 2, "µs") = "0.22µs        "
func padUnits(width int, value float64, precision int, units string) string {
    format1 := fmt.Sprintf("%%-%ds", width)
    format2 := fmt.Sprintf("%%.%df%%s", precision)
    return fmt.Sprintf(format1, fmt.Sprintf(format2, value, units))
}

// Log the current timers.  Turns off metric loggina and clears
// the metric data. Note that if we want a running tally we can
// use the go-metric log method directly, providing our registry.
func (m *Metrics) Log(scale time.Duration, l *log.Logger) {
	du := float64(scale)
	units := scale.String()[1:]

	r := m.Registry

	r.Each(func(name string, i interface{}) {
		switch metric := i.(type) {
		// Other types/metrics shown in https://github.com/rcrowley/go-metrics/blob/master/log.go#L21
		case gometrics.Timer:
			t := metric.Snapshot()
			ps := t.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
			l.Printf("%-40s count %-9d min %s max %s mean %s stddev %s median %s",
					 name, t.Count(), padUnits(14, float64(t.Min())/du, 2, units),
					 padUnits(14, float64(t.Max())/du, 2, units),
					 padUnits(14, t.Mean()/du, 2, units),
					 padUnits(14, t.StdDev()/du, 2, units),
					 padUnits(14, ps[0]/du, 2, units))
		}
	})

	m.Enabled = false
	r.UnregisterAll()
	m.Timers = make(map[string]gometrics.Timer)
}

// Returns the default log file to use.  The default is /tmp/metrics.log, but can be
// overridden by an environment variable for testing.
func getMetricsLog() (*os.File, error) {
	logfile, found := os.LookupEnv("METRICS_LOG")
	if len(logfile) == 0 || !found {
		logfile = "/tmp/metrics.log"
	}
	return os.OpenFile(logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

// Dumps the metrics to a log file.
func (m *Metrics) LogMetric(metric string) {
	file, err := getMetricsLog()
	if err != nil {
		return
	}

	w := bufio.NewWriter(file)
	defer func() {
		w.Flush()
		file.Close()
	}()

	m.Log(
		time.Second,
		log.New(w, metric, log.Lmicroseconds),
	)
}