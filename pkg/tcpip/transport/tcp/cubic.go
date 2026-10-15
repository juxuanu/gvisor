// Copyright 2018 The gVisor Authors.
//
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

package tcp

import (
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// effectivelyInfinity is an initialization value used for round-trip times
// that are then set using min.  It is equal to approximately 100 years: large
// enough that it will always be greater than a real TCP round-trip time, and
// small enough that it fits in time.Duration.
const effectivelyInfinity = time.Duration(math.MaxInt64)

const (
	// RTT = round-trip time.

	// The delay increase sensitivity is determined by minRTTThresh and
	// maxRTTThresh. Smaller values of minRTTThresh may cause spurious exits
	// from slow start. Larger values of maxRTTThresh may result in slow start
	// not exiting until loss is encountered for connections on large RTT paths.
	minRTTThresh = 4 * time.Millisecond
	maxRTTThresh = 16 * time.Millisecond

	// minRTTDivisor is a fraction of RTT to compute the delay threshold. A
	// smaller value would mean a larger threshold and thus less sensitivity to
	// delay increase, and vice versa.
	minRTTDivisor = 8

	// nRTTSample is the minimum number of RTT samples in the round before
	// considering whether to exit the round due to increased RTT.
	nRTTSample = 8

	// ackDelta is the maximum time between ACKs for them to be considered part
	// of the same ACK Train during HyStart
	ackDelta = 2 * time.Millisecond
)

// cubicState stores the variables related to TCP CUBIC congestion
// control algorithm state.
//
// See: https://tools.ietf.org/html/rfc8312.
// +stateify savable
type cubicState struct {
	TCPCubicState

	// numCongestionEvents tracks the number of congestion events since last
	// RTO.
	numCongestionEvents int

	s *sender

	// minRTT is the smallest RTT sample seen.
	minRTT time.Duration `state:"nosave"`

	// lossDiff enables loss differentiation: a loss while the RTT is close
	// to its minimum, i.e. without a standing queue, is treated as random
	// (e.g. radio loss) and doesn't reduce the window or restart the cubic
	// epoch. Losses with a standing queue get the regular CUBIC response.
	lossDiff bool `state:"nosave"`

	// roundEnd is SND.NXT when the current round trip began. roundMinRTT
	// is the smallest RTT sample of the current round trip, and roundMins
	// those of the previous ones, with roundMinsNext the next slot to fill;
	// zero means no sample.
	roundEnd      seqnum.Value                      `state:"nosave"`
	roundMinRTT   time.Duration                     `state:"nosave"`
	roundMins     [lossDiffRounds - 1]time.Duration `state:"nosave"`
	roundMinsNext int                               `state:"nosave"`

	// randomEpisode is set while recovering from a loss classified as
	// random. resumeSlowStart is set if that loss interrupted slow start.
	randomEpisode   bool `state:"nosave"`
	resumeSlowStart bool `state:"nosave"`

	// lossRounds holds per-round loss accounting for the last round trips,
	// lossNext is the next slot to fill, and lossSndNxt and lossRtx are
	// SND.NXT and the retransmission count when the current round began.
	lossRounds [8]lossRound `state:"nosave"`
	lossNext   int          `state:"nosave"`
	lossSndNxt seqnum.Value `state:"nosave"`
	lossRtx    uint64       `state:"nosave"`
}

// trackRTT updates the minimum and per-round RTTs with a sample.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) trackRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	if c.minRTT == 0 || rtt < c.minRTT {
		c.minRTT = rtt
	}
	if c.roundMinRTT == 0 || rtt < c.roundMinRTT {
		c.roundMinRTT = rtt
	}
	if c.roundEnd.LessThan(c.s.SndUna) {
		c.roundMins[c.roundMinsNext] = c.roundMinRTT
		c.roundMinsNext = (c.roundMinsNext + 1) % len(c.roundMins)
		c.roundMinRTT = 0
		c.roundEnd = c.s.SndNxt
		if c.lossDiff {
			c.recordRound()
		}
	}
}

// randomLoss reports whether a loss now looks random rather than caused by
// congestion: the smallest RTT over the last few round trips is within a
// small margin of the path's minimum, so no queue is standing at a
// bottleneck; the receiver is missing no long runs of packets; and the recent
// loss rate is low.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) randomLoss() bool {
	// Wi-Fi delay spikes last a few round trips, while a standing queue
	// persists, so take the minimum over several.
	recent := c.roundMinRTT
	for _, r := range c.roundMins {
		if r != 0 && (recent == 0 || r < recent) {
			recent = r
		}
	}
	if c.minRTT == 0 || recent == 0 {
		return false
	}
	margin := min(max(c.minRTT/4, 4*time.Millisecond), 20*time.Millisecond)
	if recent-c.minRTT >= margin {
		return false
	}
	// Random loss leaves short holes in what the receiver has (Wi-Fi loses
	// up to a few packets at once), while a queue overflowing under a burst
	// (netstack doesn't pace) drops long runs of consecutive packets, even
	// at a shallow queue that adds little delay.
	if c.s.ep.SACKPermitted && int(c.s.ep.scoreboard.LargestHole(c.s.SndUna)) > lossDiffMaxHole*c.s.MaxPayloadSize {
		return false
	}
	// A shallow bottleneck queue drops packets before it adds much delay.
	// Random loss stays at the path's loss rate, while ignoring congestion
	// drives the loss rate up, so give up on that once it's too high.
	return c.recentLossRate() < lossDiffMaxLossRate
}

// The lossdiff thresholds were tuned on a link model replaying the delay and
// loss measured on a Wi-Fi path, against shallow-buffer congestion and
// fairness with a competing CUBIC flow.
const (
	// lossDiffRounds is the number of round trips, including the current
	// one, over which the smallest RTT is compared with the minimum.
	lossDiffRounds = 8

	// lossDiffMaxLossRate is the recent retransmission rate above which
	// losses are always treated as congestion.
	lossDiffMaxLossRate = 0.05

	// lossDiffMaxHole is the largest run of consecutive missing packets,
	// as reported by SACK, that still counts as random loss.
	lossDiffMaxHole = 8
)

// lossRound counts the data sent and retransmitted in one round trip.
type lossRound struct {
	sentBytes int
	rtxPkts   uint64
}

// recordRound closes the per-round loss accounting at a round boundary.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) recordRound() {
	rtx := c.s.ep.stats.SendErrors.Retransmits.Value()
	c.lossRounds[c.lossNext] = lossRound{
		sentBytes: int(c.lossSndNxt.Size(c.s.SndNxt)),
		rtxPkts:   rtx - c.lossRtx,
	}
	c.lossNext = (c.lossNext + 1) % len(c.lossRounds)
	c.lossSndNxt = c.s.SndNxt
	c.lossRtx = rtx
}

// recentLossRate returns retransmitted over newly sent data, in packets, over
// the last few round trips including the current one.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) recentLossRate() float64 {
	sent := int(c.lossSndNxt.Size(c.s.SndNxt))
	rtx := c.s.ep.stats.SendErrors.Retransmits.Value() - c.lossRtx
	for _, r := range c.lossRounds {
		sent += r.sentBytes
		rtx += r.rtxPkts
	}
	pkts := float64(sent) / float64(c.s.MaxPayloadSize)
	if pkts < 1 {
		return 0
	}
	return float64(rtx) / pkts
}

// newCubicCC returns a partially initialized cubic state with the constants
// beta and c set and t set to current time.
//
// +checklocks:s.ep.mu
func newCubicCC(s *sender) *cubicState {
	now := s.ep.stack.Clock().NowMonotonic()
	return &cubicState{
		TCPCubicState: TCPCubicState{
			T:    now,
			Beta: 0.7,
			C:    0.4,
			// By this point, the sender has initialized it's initial sequence
			// number.
			EndSeq:  s.SndNxt,
			LastRTT: effectivelyInfinity,
			CurrRTT: effectivelyInfinity,
			// LastAck/RoundStart are seeded here from processing time, but the
			// HyStart ACK-train comparator that reads them is gated on
			// LastRTT < effectivelyInfinity, which only becomes true after the
			// first beginHyStartRound re-seeds both from an ACK's ingress time.
			// So this initial processing-time seed is never compared.
			LastAck:    now,
			RoundStart: now,
		},
		s: s,
	}
}

// enterCongestionAvoidance is used to initialize cubic in cases where we exit
// SlowStart without a real congestion event taking place. This can happen when
// a connection goes back to slow start due to a retransmit and we exceed the
// previously lowered ssThresh without experiencing packet loss.
//
// Refer: https://tools.ietf.org/html/rfc8312#section-4.8
//
// +checklocks:c.s.ep.mu
func (c *cubicState) enterCongestionAvoidance() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.7 &
	// https://tools.ietf.org/html/rfc8312#section-4.8
	if c.numCongestionEvents == 0 {
		c.K = 0
		c.T = c.s.ep.stack.Clock().NowMonotonic()
		c.WLastMax = c.WMax
		c.WMax = float64(c.s.SndCwnd)
	}
}

// updateHyStart tracks packet round-trip time (rtt) to find a safe threshold
// to exit slow start without triggering packet loss.  It updates the SSThresh
// when it does.
//
// Implementation of HyStart follows the algorithm from the Linux kernel, rather
// than RFC 9406 (https://www.rfc-editor.org/rfc/rfc9406.html). Briefly, the
// Linux kernel algorithm is based directly on the original HyStart paper
// (https://doi.org/10.1016/j.comnet.2011.01.014), and differs from the RFC in
// that two detection algorithms run in parallel ('ACK train' and 'Delay
// increase').  The RFC version includes only the latter algorithm and adds an
// intermediate phase called Conservative Slow Start, which is not implemented
// here.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) updateHyStart(rtt time.Duration, ackTime tcpip.MonotonicTime) {
	if rtt < 0 {
		// negative indicates unknown
		return
	}
	// Use the ACK's ingress time (ackTime) rather than the current clock for
	// HyStart's ACK-train timing. The ACK-train detector compares inter-ACK
	// spacing against ackDelta (2ms) and the round duration against LastRTT/2;
	// if ACKs are delayed and processed in a burst inside the stack (e.g.
	// queued while the application held the endpoint lock during a Write), the
	// processing clock would make distinct ACKs appear to arrive together,
	// distorting both comparisons and potentially exiting slow start early.
	now := ackTime
	if c.EndSeq.LessThan(c.s.SndUna) {
		c.beginHyStartRound(now)
	}
	// ACK train
	if now.Sub(c.LastAck) < ackDelta && // ensures acks are part of the same "train"
		c.LastRTT < effectivelyInfinity {
		c.LastAck = now
		if thresh := c.LastRTT / 2; now.Sub(c.RoundStart) > thresh {
			c.s.Ssthresh = c.s.SndCwnd
		}
	}

	// Delay increase
	c.CurrRTT = min(c.CurrRTT, rtt)
	c.SampleCount++

	if c.SampleCount >= nRTTSample && c.LastRTT < effectivelyInfinity {
		// i.e. LastRTT/minRTTDivisor, but clamped to minRTTThresh & maxRTTThresh
		thresh := max(
			minRTTThresh,
			min(maxRTTThresh, c.LastRTT/minRTTDivisor),
		)
		if c.CurrRTT >= (c.LastRTT + thresh) {
			// Triggered HyStart safe exit threshold
			c.s.Ssthresh = c.s.SndCwnd
		}
	}
}

// +checklocks:c.s.ep.mu
func (c *cubicState) beginHyStartRound(now tcpip.MonotonicTime) {
	c.EndSeq = c.s.SndNxt
	c.SampleCount = 0
	c.LastRTT = c.CurrRTT
	c.CurrRTT = effectivelyInfinity
	c.LastAck = now
	c.RoundStart = now
}

// updateSlowStart will update the congestion window as per the slow-start
// algorithm used by NewReno. If after adjusting the congestion window we cross
// the ssThresh then it will return the number of packets that must be consumed
// in congestion avoidance mode.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) updateSlowStart(packetsAcked int) int {
	// Don't let the congestion window cross into the congestion
	// avoidance range.
	newcwnd := c.s.SndCwnd + packetsAcked
	enterCA := false
	if newcwnd >= c.s.Ssthresh {
		newcwnd = c.s.Ssthresh
		c.s.SndCAAckCount = 0
		enterCA = true
	}

	packetsAcked -= newcwnd - c.s.SndCwnd
	c.s.SndCwnd = newcwnd
	if enterCA {
		c.enterCongestionAvoidance()
	}
	return packetsAcked
}

// Update updates cubic's internal state variables. It must be called on every
// ACK received.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
//
// +checklocks:c.s.ep.mu
// +checklocksexclude:c.s.rtt.rttMutex
func (c *cubicState) Update(packetsAcked int, rtt time.Duration, ackTime tcpip.MonotonicTime) {
	if c.lossDiff {
		c.trackRTT(rtt)
	}
	if c.s.Ssthresh == InitialSsthresh && c.s.SndCwnd < c.s.Ssthresh {
		c.updateHyStart(rtt, ackTime)
	}
	if c.s.SndCwnd < c.s.Ssthresh {
		packetsAcked = c.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	} else {
		c.s.rtt.Lock()
		srtt := c.s.rtt.TCPRTTState.SRTT
		c.s.rtt.Unlock()
		c.s.SndCwnd = c.getCwnd(packetsAcked, c.s.SndCwnd, srtt)
	}
}

// cubicCwnd computes the CUBIC congestion window after t seconds from last
// congestion event.
func (c *cubicState) cubicCwnd(t float64) float64 {
	return c.C*math.Pow(t, 3.0) + c.WMax
}

// getCwnd returns the current congestion window as computed by CUBIC.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) getCwnd(packetsAcked, sndCwnd int, srtt time.Duration) int {
	elapsed := c.s.ep.stack.Clock().NowMonotonic().Sub(c.T)
	elapsedSeconds := elapsed.Seconds()

	// Compute the window as per Cubic after 'elapsed' time
	// since last congestion event.
	c.WC = c.cubicCwnd(elapsedSeconds - c.K)

	// Compute the TCP friendly estimate of the congestion window.
	c.WEst = c.WMax*c.Beta + (3.0*((1.0-c.Beta)/(1.0+c.Beta)))*(elapsedSeconds/srtt.Seconds())

	// Make sure in the TCP friendly region CUBIC performs at least
	// as well as Reno.
	if c.WC < c.WEst && float64(sndCwnd) < c.WEst {
		// TCP Friendly region of cubic.
		return int(c.WEst)
	}

	// In Concave/Convex region of CUBIC, calculate what CUBIC window
	// will be after 1 RTT and use that to grow congestion window
	// for every ack.
	tEst := (elapsed + srtt).Seconds()
	wtRtt := c.cubicCwnd(tEst - c.K)
	// As per 4.3 for each received ACK cwnd must be incremented
	// by (w_cubic(t+RTT) - cwnd/cwnd.
	cwnd := float64(sndCwnd)
	// RFC 9438 section 4.2 bounds the target at cwnd so an ACK does not
	// reduce the congestion window.
	if wtRtt < cwnd {
		wtRtt = cwnd
	}
	for i := 0; i < packetsAcked; i++ {
		// Concave/Convex regions of cubic have the same formulas.
		// See: https://tools.ietf.org/html/rfc8312#section-4.3
		cwnd += (wtRtt - cwnd) / cwnd
	}
	return int(cwnd)
}

// HandleLossDetected implements congestionControl.HandleLossDetected.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) HandleLossDetected() {
	if c.lossDiff && c.randomLoss() {
		// Retransmit without reducing the window or restarting the
		// cubic epoch. The sender derives cwnd from ssthresh during and
		// after recovery, so pin ssthresh to cwnd until PostRecovery.
		c.randomEpisode = true
		if c.s.Ssthresh == InitialSsthresh {
			c.resumeSlowStart = true
		}
		c.s.Ssthresh = c.s.SndCwnd
		return
	}
	// See: https://tools.ietf.org/html/rfc8312#section-4.5
	c.numCongestionEvents++
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()
	c.reduceSlowStartThreshold()
}

// HandleRTOExpired implements congestionContrl.HandleRTOExpired.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) HandleRTOExpired() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.6
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.numCongestionEvents = 0
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()

	// We lost a packet, so reduce ssthresh.
	c.reduceSlowStartThreshold()

	// Reduce the congestion window to 1, i.e., enter slow-start. Per
	// RFC 5681, page 7, we must use 1 regardless of the value of the
	// initial congestion window.
	c.s.SndCwnd = 1
}

// fastConvergence implements the logic for Fast Convergence algorithm as
// described in https://tools.ietf.org/html/rfc8312#section-4.6.
func (c *cubicState) fastConvergence() {
	if c.WMax < c.WLastMax {
		c.WLastMax = c.WMax
		c.WMax = c.WMax * (1.0 + c.Beta) / 2.0
	} else {
		c.WLastMax = c.WMax
	}
	// Recompute k as wMax may have changed.
	c.K = math.Cbrt(c.WMax * (1 - c.Beta) / c.C)
}

// PostRecovery implements congestionControl.PostRecovery.
func (c *cubicState) PostRecovery() {
	if c.randomEpisode {
		c.randomEpisode = false
		if c.resumeSlowStart {
			c.resumeSlowStart = false
			c.s.Ssthresh = InitialSsthresh
		}
		return
	}
	c.T = c.s.ep.stack.Clock().NowMonotonic()
}

// cubicUndo is a snapshot of cubic's state for undoableCC.
type cubicUndo struct {
	state               TCPCubicState
	numCongestionEvents int
}

// undoState implements undoableCC.undoState.
func (c *cubicState) undoState() any {
	return cubicUndo{state: c.TCPCubicState, numCongestionEvents: c.numCongestionEvents}
}

// restoreUndoState implements undoableCC.restoreUndoState.
func (c *cubicState) restoreUndoState(v any) {
	u := v.(cubicUndo)
	c.TCPCubicState = u.state
	c.numCongestionEvents = u.numCongestionEvents
}

// reduceSlowStartThreshold returns new SsThresh as described in
// https://tools.ietf.org/html/rfc8312#section-4.7.
//
// +checklocks:c.s.ep.mu
func (c *cubicState) reduceSlowStartThreshold() {
	c.s.Ssthresh = int(math.Max(float64(c.s.SndCwnd)*c.Beta, 2.0))
}
