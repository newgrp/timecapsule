package clock

import (
	"fmt"
	"log"
	"time"

	"github.com/beevik/nts"
)

const (
	// How often the client should request a new absolute time from the NTS
	// server.
	pollPeriod = time.Hour

	// How often the client should retry failure.
	retryPeriod = 5 * time.Minute

	// How many consecutive failures the client should allow before trying a new server.
	maxConsecutiveFailures = 5
)

// Creates a new NTS session by trying to connect to each address in order.
func createSession(addrs []string) (*nts.Session, error) {
	for _, addr := range addrs {
		session, err := nts.NewSession(addr)
		if err == nil {
			log.Printf("Connected to NTS server at %s", addr)
			return session, nil
		}
		log.Printf("ERROR: failed to connect to NTS server at %s", addr)
	}
	return nil, fmt.Errorf("failed to connect to any NTS server")
}

// A reading of both NTS and system clocks.
type clockReading struct {
	nts    time.Time
	system time.Time
}

// Gets a clock reading from both NTS and the system clock.
func readTime(session *nts.Session) (clockReading, error) {
	resp, err := session.Query()
	if err != nil {
		return clockReading{}, fmt.Errorf("failed to query time from NTS server: %w", err)
	}

	// Read the system time after obtaining the NTS time in order to err on the
	// side of underestimating the current time.
	nts := resp.Time
	system := time.Now()
	return clockReading{nts: nts, system: system}, nil
}

// State for regularly polling NTS.
type ntsPoller struct {
	addrs   []string
	session *nts.Session
	cell    *muCell[clockReading]
}

// Constructs a new poller using any of the given servers.
func newPoller(addrs []string) (*ntsPoller, error) {
	session, err := createSession(addrs)
	if err != nil {
		return nil, err
	}

	initial, err := readTime(session)
	if err != nil {
		return nil, err
	}

	return &ntsPoller{
		addrs:   addrs,
		session: session,
		cell:    newCell(initial),
	}, nil
}

// Returns the cell that the poller writes its readings to.
func (p *ntsPoller) Cell() *muCell[clockReading] {
	return p.cell
}

// Updates the clock reading cell with new data, returning true on success.
//
// If reinit is true, a new NTS session is established before querying.
func (p *ntsPoller) pollOnce(reinit bool) bool {
	if reinit {
		session, err := createSession(p.addrs)
		if err != nil {
			log.Printf("ERROR: %+v", err)
			return false
		}
		p.session = session
	}

	reading, err := readTime(p.session)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return false
	}
	p.cell.Put(reading)

	return true
}

// Periodically updates the clock reading cell. Never returns.
//
// If polls fail consecutively, a new session will be established, possibly with
// a different server.
func (p *ntsPoller) PollLoop() {
	consecutiveFailures := 0
	for {
		var d time.Duration
		if consecutiveFailures > 0 {
			d = retryPeriod
		} else {
			d = pollPeriod
		}

		<-time.After(d)

		if !p.pollOnce(consecutiveFailures > maxConsecutiveFailures) {
			consecutiveFailures++
			continue
		}
		consecutiveFailures = 0
	}
}
