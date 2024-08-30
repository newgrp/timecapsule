// Package clock provides a secure clock using NTS.
package clock

import (
	"fmt"
	"time"
)

// How old NTS measurements are allowed to be.
const ntsStaleThreshold = 6 * time.Hour

// NTS-backed secure clock.
type SecureClock struct {
	cell *muCell[clockReading]
}

// Constructs a new secure clock using the given NTS server.
func NewSecureClock(ntsAddrs []string) (*SecureClock, error) {
	poller, err := newPoller(ntsAddrs)
	if err != nil {
		return nil, err
	}
	go poller.PollLoop()

	return &SecureClock{cell: poller.Cell()}, nil
}

// Returns a secure estimate of the current time.
//
// Now computes the current time as the last time obtained from the NTS server,
// plus the difference in monotonic clock readings between when Now is called
// and when the NTS response was obtained. When uncertainty arises, Now prefers
// to err on the side of underestimating the current time.
func (c *SecureClock) Now() (time.Time, error) {
	last := c.cell.Get()

	// time.Since uses the system monotic clock, rather than the realtime clock,
	// so we are not significantly exposed to NTP attacks on the system clock.
	delta := time.Since(last.system)
	if delta >= ntsStaleThreshold {
		return time.Time{}, fmt.Errorf("NTS time is too stale")
	}
	return last.nts.Add(delta), nil
}
