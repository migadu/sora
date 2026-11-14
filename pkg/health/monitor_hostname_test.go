package health

import (
	"context"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/prometheus/client_golang/prometheus"
)

// The component health metrics carry a hostname label like the other sora metrics, so
// health series from different nodes can be told apart without the scrape target. It
// was always "" (#299).
func TestHealthMetricsCarryTheNodeHostname(t *testing.T) {
	hm := NewHealthMonitor()
	name := t.Name()
	check := &HealthCheck{Name: name, Check: func(context.Context) error { return nil }}
	hm.RegisterCheck(check)
	hm.performCheck(context.Background(), check)

	want := config.ResolveMailHostname()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, mf := range families {
		switch mf.GetName() {
		case "sora_component_health_status", "sora_component_health_checks_total", "sora_component_health_check_duration_seconds":
		default:
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["component"] != name {
				continue
			}
			seen[mf.GetName()] = true
			if labels["hostname"] != want {
				t.Errorf("%s has hostname=%q, want %q", mf.GetName(), labels["hostname"], want)
			}
		}
	}
	if len(seen) != 3 {
		t.Errorf("check %s published %d of the 3 health metrics: %v", name, len(seen), seen)
	}
}
