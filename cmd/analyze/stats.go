package main

import (
	"math"
	"math/rand/v2"
	"sort"
)

// The estimators of experiment protocol section 4. They are plain functions of
// counts and samples, so each is tested against known values and none reads a
// clock or a global random source: the same inputs give the same numbers.

// Interval is a two-sided interval.
type Interval struct {
	Lo float64 `json:"lo"`
	Hi float64 `json:"hi"`
}

// ExactBound is the exact one-sided Clopper-Pearson bound the protocol uses
// when a count is 0 or n: an upper bound for 0 events, a lower bound for n of
// n.
type ExactBound struct {
	Kind  string  `json:"kind"` // "upper" or "lower"
	Alpha float64 `json:"alpha"`
	Value float64 `json:"value"`
}

// Wilson returns the Wilson score interval for k successes in n trials at the
// two-sided level the z-score zq names. It returns false for n = 0.
func Wilson(k, n int, zq float64) (Interval, bool) {
	if n <= 0 || k < 0 || k > n {
		return Interval{}, false
	}
	nf, p := float64(n), float64(k)/float64(n)
	z2 := zq * zq
	denom := 1 + z2/nf
	center := (p + z2/(2*nf)) / denom
	half := zq * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf)) / denom
	lo, hi := center-half, center+half
	// At the edges the interval ends at 0 or 1 exactly; the arithmetic above
	// leaves a rounding residue.
	if k == 0 {
		lo = 0
	}
	if k == n {
		hi = 1
	}
	return Interval{Lo: math.Max(0, lo), Hi: math.Min(1, hi)}, true
}

// binomCDF is P(X <= k) for X ~ Binomial(n, p), summed in log space.
func binomCDF(k, n int, p float64) float64 {
	if k < 0 {
		return 0
	}
	if k >= n {
		return 1
	}
	if p <= 0 {
		return 1
	}
	if p >= 1 {
		return 0
	}
	lgn, _ := math.Lgamma(float64(n) + 1)
	sum := 0.0
	for i := 0; i <= k; i++ {
		lgi, _ := math.Lgamma(float64(i) + 1)
		lgni, _ := math.Lgamma(float64(n-i) + 1)
		sum += math.Exp(lgn - lgi - lgni + float64(i)*math.Log(p) + float64(n-i)*math.Log1p(-p))
	}
	return math.Min(1, sum)
}

// ClopperPearsonUpper is the exact one-sided upper confidence bound at level
// 1-alpha for k events in n trials: the p at which P(X <= k) falls to alpha.
func ClopperPearsonUpper(k, n int, alpha float64) float64 {
	switch {
	case n <= 0 || k < 0 || k > n:
		return math.NaN()
	case k == n:
		return 1
	case k == 0:
		return 1 - math.Pow(alpha, 1/float64(n))
	}
	lo, hi := 0.0, 1.0
	for range 200 {
		mid := (lo + hi) / 2
		if binomCDF(k, n, mid) > alpha {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// ClopperPearsonLower is the exact one-sided lower confidence bound at level
// 1-alpha: the p at which P(X >= k) rises to alpha.
func ClopperPearsonLower(k, n int, alpha float64) float64 {
	switch {
	case n <= 0 || k < 0 || k > n:
		return math.NaN()
	case k == 0:
		return 0
	case k == n:
		return math.Pow(alpha, 1/float64(n))
	}
	lo, hi := 0.0, 1.0
	for range 200 {
		mid := (lo + hi) / 2
		if 1-binomCDF(k-1, n, mid) < alpha {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// ExactEdge returns the protocol's exact bound when k is 0 (upper) or n
// (lower), and nil otherwise.
func ExactEdge(k, n int, alpha float64) *ExactBound {
	switch {
	case n <= 0:
		return nil
	case k == 0:
		return &ExactBound{Kind: "upper", Alpha: alpha, Value: ClopperPearsonUpper(0, n, alpha)}
	case k == n:
		return &ExactBound{Kind: "lower", Alpha: alpha, Value: ClopperPearsonLower(n, n, alpha)}
	}
	return nil
}

// Rate is a proportion over runs with the three counts of
// being_data_driven.md section 8 and the protocol's interval rules.
type Rate struct {
	// Considered is how many items were in scope, Evaluated how many the
	// measurement could be made on (the denominator), Succeeded the
	// numerator: the items that have the property the rate names.
	Considered   int            `json:"considered"`
	Evaluated    int            `json:"evaluated"`
	Succeeded    int            `json:"succeeded"`
	NotEvaluated map[string]int `json:"not_evaluated,omitempty"`
	Rate         *float64       `json:"rate"`
	Wilson       *Interval      `json:"wilson95,omitempty"`
	Exact        *ExactBound    `json:"exact_one_sided95,omitempty"`
}

// NewRate builds a Rate over runs: a Wilson 95% interval, and the exact
// one-sided 95% bound when the count is 0 or n.
func NewRate(considered, evaluated, succeeded int, notEvaluated map[string]int) Rate {
	r := Rate{Considered: considered, Evaluated: evaluated, Succeeded: succeeded}
	if len(notEvaluated) > 0 {
		r.NotEvaluated = notEvaluated
	}
	if evaluated > 0 {
		p := float64(succeeded) / float64(evaluated)
		r.Rate = &p
		if w, ok := Wilson(succeeded, evaluated, ZScore95); ok {
			r.Wilson = &w
		}
		r.Exact = ExactEdge(succeeded, evaluated, OneSidedAlpha)
	}
	return r
}

// Cluster is one session's contribution to a rate over mutations or claims:
// a shared denominator and one numerator per rate.
type Cluster struct {
	Den  float64
	Nums []float64
}

// ClusterRate is a pooled rate with a percentile interval from a bootstrap
// that resamples whole clusters (sessions).
type ClusterRate struct {
	Num  float64   `json:"num"`
	Den  float64   `json:"den"`
	Rate *float64  `json:"rate"`
	CI   *Interval `json:"bootstrap95,omitempty"`
	// PerClusterMin is the lowest rate among clusters with a denominator.
	PerClusterMin *float64 `json:"per_session_min,omitempty"`
}

// quantileSorted is the linear-interpolation quantile (R type 7, the method of
// Python's statistics.quantiles with method inclusive) of sorted values.
func quantileSorted(v []float64, q float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	if len(v) == 1 {
		return v[0]
	}
	pos := q * float64(len(v)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return v[lo]
	}
	return v[lo] + (v[hi]-v[lo])*(pos-float64(lo))
}

func newRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}

// ClusterBootstrap pools the clusters into one ratio per numerator and gives
// each a percentile interval from resamples of the clusters with replacement.
// A resample whose denominator is zero has no ratio and is left out. The same
// clusters, resample count and seed give the same result.
func ClusterBootstrap(clusters []Cluster, nNums, resamples int, seed uint64) []ClusterRate {
	out := make([]ClusterRate, nNums)
	totalDen := 0.0
	totalNum := make([]float64, nNums)
	for _, c := range clusters {
		totalDen += c.Den
		for i := range nNums {
			totalNum[i] += c.Nums[i]
		}
	}
	for i := range nNums {
		out[i].Num, out[i].Den = totalNum[i], totalDen
		if totalDen > 0 {
			p := totalNum[i] / totalDen
			out[i].Rate = &p
		}
		minR := math.Inf(1)
		for _, c := range clusters {
			if c.Den > 0 {
				minR = math.Min(minR, c.Nums[i]/c.Den)
			}
		}
		if !math.IsInf(minR, 1) {
			out[i].PerClusterMin = &minR
		}
	}
	if len(clusters) == 0 || totalDen == 0 || resamples <= 0 {
		return out
	}
	r := newRand(seed)
	ratios := make([][]float64, nNums)
	for range resamples {
		den := 0.0
		nums := make([]float64, nNums)
		for range clusters {
			c := clusters[r.IntN(len(clusters))]
			den += c.Den
			for i := range nNums {
				nums[i] += c.Nums[i]
			}
		}
		if den == 0 {
			continue
		}
		for i := range nNums {
			ratios[i] = append(ratios[i], nums[i]/den)
		}
	}
	for i := range nNums {
		if len(ratios[i]) == 0 {
			continue
		}
		sort.Float64s(ratios[i])
		out[i].CI = &Interval{
			Lo: quantileSorted(ratios[i], (1-ConfidenceLevel)/2),
			Hi: quantileSorted(ratios[i], 1-(1-ConfidenceLevel)/2),
		}
	}
	return out
}

// BootstrapMedian is a percentile interval for the median of values, from
// resamples of the values with replacement.
func BootstrapMedian(values []float64, resamples int, seed uint64) (Interval, bool) {
	if len(values) == 0 || resamples <= 0 {
		return Interval{}, false
	}
	r := newRand(seed)
	meds := make([]float64, 0, resamples)
	buf := make([]float64, len(values))
	for range resamples {
		for i := range buf {
			buf[i] = values[r.IntN(len(values))]
		}
		sort.Float64s(buf)
		meds = append(meds, quantileSorted(buf, 0.5))
	}
	sort.Float64s(meds)
	return Interval{Lo: quantileSorted(meds, (1-ConfidenceLevel)/2), Hi: quantileSorted(meds, 1-(1-ConfidenceLevel)/2)}, true
}

// Summary is the timing summary of the protocol: median, quartiles and top1,
// the largest single observation (being_data_driven.md section 8).
type Summary struct {
	N      int     `json:"n"`
	Median float64 `json:"median"`
	Q1     float64 `json:"q1"`
	Q3     float64 `json:"q3"`
	Top1   float64 `json:"top1"`
}

// Summarize returns the summary of values, or false when there are none.
func Summarize(values []float64) (Summary, bool) {
	if len(values) == 0 {
		return Summary{}, false
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	return Summary{N: len(v), Median: quantileSorted(v, 0.5), Q1: quantileSorted(v, 0.25), Q3: quantileSorted(v, 0.75), Top1: v[len(v)-1]}, true
}

func fptr(x float64) *float64 { return &x }

func ratioPtr(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	return fptr(float64(num) / float64(den))
}
