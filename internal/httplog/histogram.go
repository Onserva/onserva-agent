package httplog

import "sort"

// Latency buckets in milliseconds, closely spaced where web requests actually
// live and coarse in the tail.
//
// Why a histogram rather than keeping the durations: a busy server can serve
// tens of thousands of requests between two samples, and holding every duration
// would mean the monitoring agent's memory growing with the traffic it is
// watching. This is thirty-odd counters, no matter the load.
//
// The cost is that percentiles are approximate — accurate to about the width of
// the bucket they land in. For "is the site getting slower", that is the right
// trade. For billing-grade timing, it would not be.
var bucketBoundsMs = []float64{
	1, 2, 3, 4, 5, 7, 10, 15, 20, 30, 40, 50, 75, 100, 150, 200, 300, 400, 500,
	750, 1000, 1500, 2000, 3000, 5000, 7500, 10000, 15000, 20000, 30000, 60000,
}

// histogram counts observations per bucket, plus everything past the last bound.
type histogram struct {
	counts   []int64 // len(bucketBoundsMs)+1; the last is the overflow bucket
	total    int64
	maxSeen  float64
	minSeen  float64
	haveSeen bool
}

func newHistogram() *histogram {
	return &histogram{counts: make([]int64, len(bucketBoundsMs)+1)}
}

func (h *histogram) observe(ms float64) {
	if ms < 0 {
		return
	}
	index := sort.SearchFloat64s(bucketBoundsMs, ms)
	h.counts[index]++
	h.total++

	if !h.haveSeen {
		h.minSeen, h.maxSeen, h.haveSeen = ms, ms, true
		return
	}
	if ms < h.minSeen {
		h.minSeen = ms
	}
	if ms > h.maxSeen {
		h.maxSeen = ms
	}
}

func (h *histogram) reset() {
	for i := range h.counts {
		h.counts[i] = 0
	}
	h.total = 0
	h.haveSeen = false
	h.minSeen, h.maxSeen = 0, 0
}

// quantile returns the approximate value at p (0..1), or false if nothing has
// been observed. Within a bucket it interpolates linearly, which is a guess —
// but a better one than always reporting the bucket's upper bound.
func (h *histogram) quantile(p float64) (float64, bool) {
	if h.total == 0 {
		return 0, false
	}
	if p <= 0 {
		return h.minSeen, true
	}
	if p >= 1 {
		return h.maxSeen, true
	}

	target := p * float64(h.total)
	var cumulative float64

	for i, count := range h.counts {
		if count == 0 {
			continue
		}
		next := cumulative + float64(count)
		if next < target {
			cumulative = next
			continue
		}

		lower := 0.0
		if i > 0 {
			lower = bucketBoundsMs[i-1]
		}
		// The overflow bucket has no upper bound; the largest value actually
		// seen is the most honest thing to report.
		upper := h.maxSeen
		if i < len(bucketBoundsMs) {
			upper = bucketBoundsMs[i]
		}
		if upper < lower {
			upper = lower
		}

		// Where in this bucket does the target fall?
		position := (target - cumulative) / float64(count)
		value := lower + (upper-lower)*position

		// Never claim a figure outside what was actually observed.
		if value < h.minSeen {
			value = h.minSeen
		}
		if value > h.maxSeen {
			value = h.maxSeen
		}
		return value, true
	}

	return h.maxSeen, true
}
