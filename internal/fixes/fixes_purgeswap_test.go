package fixes

import (
	"strings"
	"testing"
)

func meminfo(availableKB, swapTotalKB, swapFreeKB int64) string {
	return strings.Join([]string{
		"MemTotal:       16000000 kB",
		"MemAvailable:   " + itoa(availableKB) + " kB",
		"SwapTotal:      " + itoa(swapTotalKB) + " kB",
		"SwapFree:       " + itoa(swapFreeKB) + " kB",
	}, "\n")
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// The guard is the difference between a housekeeping button and a footgun:
// purging forces every parked page back into RAM at once, so free memory
// must comfortably exceed what is parked.
func TestSwapPurgeVerdict(t *testing.T) {
	// Plenty of headroom: 8 GB available, 1 GB parked.
	if ok, used, _ := SwapPurgeVerdict(meminfo(8_000_000, 4_000_000, 3_000_000)); !ok || used != 1_000_000 {
		t.Fatalf("comfortable purge refused: ok=%v used=%d", ok, used)
	}

	// Exactly 1.5x is the line; just under it refuses.
	if ok, _, detail := SwapPurgeVerdict(meminfo(1_499_999, 4_000_000, 3_000_000)); ok {
		t.Fatal("tight purge was allowed")
	} else if !strings.Contains(detail, "not enough free memory") {
		t.Fatalf("refusal does not explain itself: %q", detail)
	}

	// Nothing parked: always safe (a no-op re-arm).
	if ok, used, _ := SwapPurgeVerdict(meminfo(100_000, 4_000_000, 4_000_000)); !ok || used != 0 {
		t.Fatal("empty swap purge refused")
	}

	// No swap at all: nothing to purge, said plainly.
	if ok, _, detail := SwapPurgeVerdict(meminfo(8_000_000, 0, 0)); ok {
		t.Fatal("swapless machine allowed a purge")
	} else if !strings.Contains(detail, "no swap configured") {
		t.Fatalf("wrong refusal: %q", detail)
	}

	// Unreadable figures fail CLOSED.
	if ok, _, _ := SwapPurgeVerdict("garbage"); ok {
		t.Fatal("unreadable meminfo allowed a purge")
	}
	// Inconsistent figures (free > total) fail closed too.
	if ok, _, _ := SwapPurgeVerdict(meminfo(8_000_000, 1_000, 2_000)); ok {
		t.Fatal("inconsistent meminfo allowed a purge")
	}
}
