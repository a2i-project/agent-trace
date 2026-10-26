package main

import (
	"math"
	"reflect"
	"testing"
)

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %.9f, want %.9f (tolerance %g)", name, got, want, tol)
	}
}

// Reference values computed independently (Python, exact arithmetic on the
// binomial distribution and the Wilson formula).
func TestWilsonKnownValues(t *testing.T) {
	cases := []struct {
		k, n   int
		lo, hi float64
	}{
		{3, 10, 0.107791267, 0.603221853},
		{0, 60, 0, 0.060171852},
		{30, 60, 0.377350242, 0.622649758},
		{1, 5, 0.036224109, 0.624465370},
	}
	for _, c := range cases {
		w, ok := Wilson(c.k, c.n, ZScore95)
		if !ok {
			t.Fatalf("Wilson(%d, %d) is undefined", c.k, c.n)
		}
		near(t, "lo", w.Lo, c.lo, 1e-8)
		near(t, "hi", w.Hi, c.hi, 1e-8)
	}
	if _, ok := Wilson(0, 0, ZScore95); ok {
		t.Error("Wilson of zero trials must be undefined, not a number")
	}
	if _, ok := Wilson(5, 3, ZScore95); ok {
		t.Error("Wilson with more successes than trials must be undefined")
	}
	if w, _ := Wilson(10, 10, ZScore95); w.Hi != 1 {
		t.Errorf("Wilson at n of n must end at 1, got %v", w.Hi)
	}
}

// The protocol quotes the bound at 0 events: 4.9% at n=60, 9.5% at n=30 and
// 3.0% at n=100 (section 6.4).
func TestClopperPearsonZeroEventsMatchTheProtocolsFigures(t *testing.T) {
	for _, c := range []struct {
		n    int
		want float64
	}{{30, 0.0950338529}, {60, 0.0487029133}, {100, 0.0295130496}} {
		got := ClopperPearsonUpper(0, c.n, OneSidedAlpha)
		near(t, "upper at 0 events", got, c.want, 1e-9)
	}
	if b := ExactEdge(0, 60, OneSidedAlpha); b == nil || b.Kind != "upper" {
		t.Errorf("0 of 60 must give the upper bound, got %+v", b)
	}
	if b := ExactEdge(60, 60, OneSidedAlpha); b == nil || b.Kind != "lower" {
		t.Errorf("60 of 60 must give the lower bound, got %+v", b)
	}
	if b := ExactEdge(5, 60, OneSidedAlpha); b != nil {
		t.Errorf("5 of 60 is not an edge, got %+v", b)
	}
}

func TestClopperPearsonGeneralBounds(t *testing.T) {
	near(t, "upper 1/10", ClopperPearsonUpper(1, 10, 0.05), 0.3941633024, 1e-8)
	near(t, "upper 3/20", ClopperPearsonUpper(3, 20, 0.05), 0.3436638043, 1e-8)
	near(t, "lower 9/10", ClopperPearsonLower(9, 10, 0.05), 0.6058366976, 1e-8)
	near(t, "lower 5/20", ClopperPearsonLower(5, 20, 0.05), 0.1040808359, 1e-8)
	// The closed forms at the edges agree with the general bisection one step
	// inside them, by continuity.
	near(t, "n of n", ClopperPearsonLower(60, 60, 0.05), math.Pow(0.05, 1.0/60), 1e-12)
	near(t, "upper at n", ClopperPearsonUpper(7, 7, 0.05), 1, 0)
	near(t, "lower at 0", ClopperPearsonLower(0, 7, 0.05), 0, 0)
	if !math.IsNaN(ClopperPearsonUpper(1, 0, 0.05)) {
		t.Error("a bound over zero trials must be NaN, not a number")
	}
}

func TestNewRateCarriesTheThreeCountsAndTheRightBound(t *testing.T) {
	r := NewRate(63, 60, 0, map[string]int{"excluded X4": 3})
	if r.Considered != 63 || r.Evaluated != 60 || r.Succeeded != 0 || r.NotEvaluated["excluded X4"] != 3 {
		t.Errorf("counts lost: %+v", r)
	}
	if r.Rate == nil || *r.Rate != 0 || r.Exact == nil || r.Exact.Kind != "upper" || r.Wilson == nil {
		t.Errorf("a rate of 0 of 60 needs the point estimate, Wilson and the exact upper bound: %+v", r)
	}
	if e := NewRate(0, 0, 0, nil); e.Rate != nil || e.Wilson != nil || e.Exact != nil {
		t.Errorf("no evaluated run must give no rate, not a zero rate: %+v", e)
	}
	if m := NewRate(10, 10, 4, nil); m.Exact != nil {
		t.Errorf("4 of 10 gets no exact edge bound: %+v", m)
	}
}

func TestQuantileAndSummary(t *testing.T) {
	s, ok := Summarize([]float64{9, 1, 5, 3, 7, 2, 4, 6, 8})
	if !ok {
		t.Fatal("no summary")
	}
	// R type 7 on 1..9: q1 = 3, median 5, q3 = 7; top1 is the largest observation.
	if s.N != 9 || s.Median != 5 || s.Q1 != 3 || s.Q3 != 7 || s.Top1 != 9 {
		t.Errorf("summary %+v", s)
	}
	s, _ = Summarize([]float64{1, 2, 3, 4})
	near(t, "interpolated median", s.Median, 2.5, 1e-12)
	near(t, "interpolated q1", s.Q1, 1.75, 1e-12)
	if _, ok := Summarize(nil); ok {
		t.Error("an empty sample has no summary")
	}
}

func bernoulliClusters(n, ones int) []Cluster {
	out := make([]Cluster, n)
	for i := range out {
		out[i] = Cluster{Den: 1, Nums: []float64{0}}
		if i < ones {
			out[i].Nums[0] = 1
		}
	}
	return out
}

func TestClusterBootstrapIsDeterministic(t *testing.T) {
	cl := bernoulliClusters(20, 10)
	a := ClusterBootstrap(cl, 1, BootstrapResamples, BootstrapSeed)
	b := ClusterBootstrap(cl, 1, BootstrapResamples, BootstrapSeed)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the same clusters and seed gave two results: %+v and %+v", a, b)
	}
	// Uneven sessions make the resampled ratios nearly continuous, so a
	// different seed shows as a different interval.
	var uneven []Cluster
	for i := range 30 {
		uneven = append(uneven, Cluster{Den: float64(i + 1), Nums: []float64{float64((i * 7) % (i + 2))}})
	}
	x := ClusterBootstrap(uneven, 1, BootstrapResamples, BootstrapSeed)
	y := ClusterBootstrap(uneven, 1, BootstrapResamples, BootstrapSeed+1)
	if reflect.DeepEqual(x[0].CI, y[0].CI) {
		t.Error("a different seed gave the identical interval: the seed is not used")
	}
}

func TestClusterBootstrapKnownCases(t *testing.T) {
	// All clusters at 1: the interval is the point.
	all := ClusterBootstrap(bernoulliClusters(8, 8), 1, 2000, BootstrapSeed)
	if all[0].CI == nil || all[0].CI.Lo != 1 || all[0].CI.Hi != 1 || *all[0].Rate != 1 {
		t.Errorf("all-one clusters: %+v", all[0])
	}
	// Twenty fair coin sessions: the percentile interval of the mean is close to
	// the normal approximation 0.5 +- 1.96 * sqrt(0.25 / 20) = [0.28, 0.72].
	half := ClusterBootstrap(bernoulliClusters(20, 10), 1, BootstrapResamples, BootstrapSeed)[0]
	near(t, "point", *half.Rate, 0.5, 0)
	near(t, "lo", half.CI.Lo, 0.30, 0.05)
	near(t, "hi", half.CI.Hi, 0.70, 0.05)
	// Sessions weigh by their denominators: 90 of 100 in one session and 0 of 1
	// in another pool to 90 of 101.
	w := ClusterBootstrap([]Cluster{{Den: 100, Nums: []float64{90}}, {Den: 1, Nums: []float64{0}}}, 1, 500, BootstrapSeed)[0]
	near(t, "pooled rate", *w.Rate, 90.0/101, 1e-12)
	if w.PerClusterMin == nil || *w.PerClusterMin != 0 {
		t.Errorf("the per-session minimum is the lowest session rate, got %v", w.PerClusterMin)
	}
	// No denominator: no rate, no interval.
	none := ClusterBootstrap([]Cluster{{Den: 0, Nums: []float64{0}}}, 1, 100, BootstrapSeed)[0]
	if none.Rate != nil || none.CI != nil {
		t.Errorf("zero denominator must give no rate: %+v", none)
	}
}

func TestClusterBootstrapSeveralRatesShareResamples(t *testing.T) {
	cl := []Cluster{{Den: 10, Nums: []float64{10, 9, 8}}, {Den: 10, Nums: []float64{10, 10, 5}}, {Den: 4, Nums: []float64{4, 1, 1}}}
	got := ClusterBootstrap(cl, 3, 1000, BootstrapSeed)
	if len(got) != 3 {
		t.Fatalf("want three rates, got %d", len(got))
	}
	// Ordered numerators give ordered rates in every resample, so the intervals are ordered.
	if !(got[0].CI.Lo >= got[1].CI.Lo && got[1].CI.Lo >= got[2].CI.Lo && got[0].CI.Hi >= got[1].CI.Hi && got[1].CI.Hi >= got[2].CI.Hi) {
		t.Errorf("intervals out of order: %+v %+v %+v", got[0].CI, got[1].CI, got[2].CI)
	}
}

func TestBootstrapMedian(t *testing.T) {
	v := []float64{1.00, 1.02, 1.04, 1.06, 1.08, 1.10, 1.12}
	a, ok := BootstrapMedian(v, 5000, BootstrapSeed)
	b, _ := BootstrapMedian(v, 5000, BootstrapSeed)
	if !ok || a != b {
		t.Errorf("median bootstrap not deterministic: %+v %+v", a, b)
	}
	if a.Lo < 1.00 || a.Hi > 1.12 || a.Lo >= a.Hi {
		t.Errorf("interval %+v must lie inside the sample's range", a)
	}
	if _, ok := BootstrapMedian(nil, 100, 1); ok {
		t.Error("an empty sample has no interval")
	}
}
