// Copyright 2026 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// undoableCC is implemented by congestion control algorithms that keep state
// beyond SndCwnd and Ssthresh which must be restored when a window reduction
// is undone.
type undoableCC interface {
	// undoState returns a snapshot of the algorithm's state.
	undoState() any

	// restoreUndoState restores a snapshot returned by undoState.
	restoreUndoState(any)
}

// congestionUndo holds the congestion state saved when the sender reduces its
// window in response to presumed loss (fast recovery, RACK or RTO), so that
// the reduction can be reverted if the loss later proves spurious, e.g.
// because the path delayed packets instead of dropping them.
//
// Following RFC 4015 and Linux's tcp_try_undo_*, two signals prove a loss
// spurious:
//   - Eifel detection (RFC 3522): the first ACK covering the episode's first
//     retransmission echoes a timestamp older than that retransmission, so an
//     original transmission arrived.
//   - DSACK (RFC 3708): every retransmission in the episode was reported as a
//     duplicate by the receiver.
type congestionUndo struct {
	// active is set while a snapshot is held.
	active bool

	// rto is set if the episode began with a retransmission timeout.
	rto bool

	// marker is SND.UNA when the episode began. DSACKs below it report
	// retransmissions from earlier episodes.
	marker seqnum.Value

	// sndCwnd, ssthresh and cc are the congestion state before the
	// reduction.
	sndCwnd  int
	ssthresh int
	cc       any

	// rtxSent is set once the episode retransmitted data. rtxSeq and tsVal
	// are the sequence number and TSval of its first retransmission.
	rtxSent bool
	rtxSeq  seqnum.Value
	tsVal   uint32

	// tsChecked is set once the Eifel check has run for this episode.
	tsChecked bool

	// retrans is the number of packets retransmitted in the episode that
	// the receiver has not yet reported as duplicates.
	retrans int
}

// handleLossDetected snapshots the congestion state for a possible undo and
// then lets the congestion control algorithm respond to the loss.
//
// +checklocks:s.ep.mu
func (s *sender) handleLossDetected() {
	s.beginUndoEpisode(false /* rto */)
	s.cc.HandleLossDetected()
}

// beginUndoEpisode snapshots the congestion state before a loss response
// reduces it. Within an ongoing episode the earliest snapshot is kept, except
// that an RTO during fast recovery starts a new episode: its go-back-N
// retransmissions are judged separately from the fast retransmits.
//
// +checklocks:s.ep.mu
func (s *sender) beginUndoEpisode(rto bool) {
	if s.undo.active && s.inRecovery() && (!rto || s.state == tcpip.RTORecovery) {
		return
	}
	s.undo = congestionUndo{
		active:   true,
		rto:      rto,
		marker:   s.SndUna,
		sndCwnd:  s.SndCwnd,
		ssthresh: s.Ssthresh,
	}
	if u, ok := s.cc.(undoableCC); ok {
		s.undo.cc = u.undoState()
	}
}

// noteRetransmit accounts a retransmission sent during loss recovery.
//
// +checklocks:s.ep.mu
func (s *sender) noteRetransmit(seg *segment) {
	if !s.undo.active || !s.inRecovery() {
		return
	}
	if !s.undo.rtxSent {
		s.undo.rtxSent = true
		s.undo.rtxSeq = seg.sequenceNumber
		// Read before the segment is stamped, so this is at most the TSval
		// it carries; an echo of the retransmission is never mistaken for an
		// echo of an earlier transmission.
		s.undo.tsVal = s.ep.tsValNow()
	}
	s.undo.retrans += s.pCount(seg, s.MaxPayloadSize)
}

// checkUndoOnDSACK accounts a DSACK reporting a duplicate retransmission, and
// undoes the episode's window reduction once the receiver has reported every
// retransmission as a duplicate.
//
// +checklocks:s.ep.mu
func (s *sender) checkUndoOnDSACK(rcvdSeg *segment) {
	if !s.undo.active || !s.undo.rtxSent || !checkDSACK(rcvdSeg) {
		return
	}
	sb := rcvdSeg.parsedOptions.SACKBlocks[0]
	if sb.Start.LessThan(s.undo.marker) {
		return
	}
	s.undo.retrans -= (int(sb.Start.Size(sb.End)) + s.MaxPayloadSize - 1) / s.MaxPayloadSize
	if s.undo.retrans <= 0 {
		s.undoCongestionReduction()
	}
}

// checkUndoOnAck runs Eifel detection (RFC 3522) on an ACK that advanced
// SND.UNA. If the first ACK covering the episode's first retransmission echoes
// an older timestamp, the original transmission arrived and the episode's
// window reduction is undone.
//
// +checklocks:s.ep.mu
func (s *sender) checkUndoOnAck(rcvdSeg *segment) {
	u := &s.undo
	if !u.active || !u.rtxSent || u.tsChecked || !u.rtxSeq.LessThan(s.SndUna) {
		return
	}
	u.tsChecked = true
	if !s.ep.SendTSOk || !rcvdSeg.parsedOptions.TS || rcvdSeg.parsedOptions.TSEcr == 0 {
		return
	}
	if int32(rcvdSeg.parsedOptions.TSEcr-u.tsVal) < 0 {
		s.undoCongestionReduction()
	}
}

// undoCongestionReduction reverts the current episode's window reduction after
// the loss proved spurious, and leaves loss recovery.
//
// +checklocks:s.ep.mu
func (s *sender) undoCongestionReduction() {
	u := s.undo
	s.undo = congestionUndo{}
	if !u.active {
		return
	}
	s.ep.stack.Stats().TCP.SpuriousRecoveryUndo.Increment()

	if s.FastRecovery.Active {
		s.leaveRecovery()
	}
	s.SndCwnd = max(s.SndCwnd, u.sndCwnd)
	s.Ssthresh = max(s.Ssthresh, u.ssthresh)
	if u.cc != nil {
		s.cc.(undoableCC).restoreUndoState(u.cc)
	}

	if wn := s.writeNext; wn != nil && s.isAssignedSequenceNumber(wn) && wn.sequenceNumber.LessThan(s.SndNxt) {
		// An RTO rewound writeNext to SND.UNA and zeroed Outstanding to
		// retransmit everything in flight (go-back-N). That data was not
		// lost, so resume with never-sent data and count the unSACKed rest
		// as outstanding again. Check the rewind itself rather than the
		// RTORecovery state: a later ACK may have moved the sender into
		// SACK recovery since.
		s.Outstanding = 0
		var next *segment
		for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
			if !s.isAssignedSequenceNumber(seg) || !seg.sequenceNumber.LessThan(s.SndNxt) {
				next = seg
				break
			}
			if !s.ep.SACKPermitted || !s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
			}
		}
		s.updateWriteNext(next)
	}

	// Segments RACK marked lost were not, so don't retransmit them or let
	// them trigger another recovery.
	for seg := s.writeList.Front(); seg != nil && seg != s.writeNext; seg = seg.Next() {
		seg.lost = false
	}

	if s.inRecovery() {
		s.state = tcpip.Open
		if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
			s.rc.exitRecovery()
		}
	}
}
