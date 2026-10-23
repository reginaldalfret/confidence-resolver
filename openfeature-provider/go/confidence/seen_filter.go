package confidence

import (
	"sync"
	"time"
)

// seenFilter defaults.
const (
	seenFilterTTL     = 10 * time.Minute
	seenFilterMaxKeys = 65536
)

// seenFilter is the host-side de-duplication set behind the module's
// apply_filter.seen and schema_filter.seen imports: it remembers reported
// fingerprints for a TTL window so repeated identical assignments or schema
// payloads are logged once instead of on every resolve.
//
// When disabled (disabled), every lookup reports "not seen", which turns
// de-duplication off: correct, but it sends more exposure events.
type seenFilter struct {
	mu       sync.Mutex
	seen     map[int64]time.Time
	disabled bool
	ttl      time.Duration
	maxKeys  int
	now      func() time.Time
}

func newSeenFilter(disabled bool) *seenFilter {
	return &seenFilter{
		seen:     make(map[int64]time.Time),
		disabled: disabled,
		ttl:      seenFilterTTL,
		maxKeys:  seenFilterMaxKeys,
		now:      time.Now,
	}
}

// Seen reports whether the fingerprint was already reported, recording it
// when not.
func (f *seenFilter) Seen(fingerprint int64) bool {
	if f == nil || f.disabled {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if stamp, ok := f.seen[fingerprint]; ok {
		if now.Sub(stamp) < f.ttl {
			return true
		}
		// Expired: fall through to re-record.
	}

	if len(f.seen) >= f.maxKeys {
		// Bound the set: drop expired entries first, then evict the oldest
		// remaining one to admit the new fingerprint.
		f.evictExpiredLocked(now)
		if len(f.seen) >= f.maxKeys {
			f.evictOneLocked()
		}
	}
	f.seen[fingerprint] = now
	return false
}

func (f *seenFilter) evictExpiredLocked(now time.Time) {
	for key, stamp := range f.seen {
		if now.Sub(stamp) >= f.ttl {
			delete(f.seen, key)
		}
	}
}

func (f *seenFilter) evictOneLocked() {
	var oldestKey int64
	var oldestStamp time.Time
	first := true
	for key, stamp := range f.seen {
		if first || stamp.Before(oldestStamp) {
			oldestKey, oldestStamp = key, stamp
			first = false
		}
	}
	if !first {
		delete(f.seen, oldestKey)
	}
}
