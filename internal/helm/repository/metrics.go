/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package repository

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"time"
)

const (
	ChartRepoTypeHelm = "helm"
	//ChartRepoTypeOCI                = "oci"
	ChartRepoEventTypeDownloadIndex = "chart_repository_download"
	ChartRepoEventTypeDownloadChart = "chart_download"
)

// Recorder is a recorder for chart repository events.
type Recorder struct {
	// TODO: type up the metrics and talk to aryan9600
	// TODO: split this counter??
	chartRepoEventsCounter *prometheus.CounterVec
	durationHistogram      *prometheus.HistogramVec
}

// NewRepositoryRecorder returns a new Recorder.
// The configured labels are: event_type, name, namespace.
// The event_type is one of:
//   - "chart_repository_download"
//   - "chart_download"
// The url is the url of the helm chart repository
func NewRepositoryRecorder() *Recorder {
	return &Recorder{
		chartRepoEventsCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gotk_chart_repository_events_total",
				Help: "Total number of events for a Helm Chart Repository.",
			},
			[]string{"name", "repo_type", "namespace", "url", "checksum"},
		),
		durationHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gotk_chart_repository_event_duration_seconds",
				Help:    "The duration in seconds of an event for a Helm Chart Repository.",
				Buckets: prometheus.ExponentialBuckets(10e-9, 10, 10),
			},
			[]string{"name", "repo_type", "namespace", "url", "checksum"},
		),
	}
}

// ChartRepoCollectors returns the metrics.Collector objects for the Recorder.
func (r *Recorder) ChartRepoCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		r.chartRepoEventsCounter,
		r.durationHistogram,
	}
}

// IncChartRepoEvents increment by 1 the chart repo event count for the given event type, url and checksum.
func (r *Recorder) IncChartRepoEvents(event, repoType, url, checksum, namespace string) {
	r.chartRepoEventsCounter.WithLabelValues(event, repoType, url, checksum, namespace).Inc()
}

// RecordChartRepoEventDuration records the duration since start for the given ref.
func (r *Recorder) RecordChartRepoEventDuration(event, repoType, namespace, url string, start time.Time) {
	r.durationHistogram.WithLabelValues(event, repoType, namespace, url).Observe(time.Since(start).Seconds())
}

// MustMakeMetrics creates a new Recorder, and registers the metrics collectors in the controller-runtime metrics registry.
func MustMakeMetrics() *Recorder {
	r := NewRepositoryRecorder()
	metrics.Registry.MustRegister(r.ChartRepoCollectors()...)

	return r
}
