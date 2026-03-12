// Copyright (C) The Retina Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP and RTCP handling; see [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550).

use std::collections::VecDeque;

use bytes::Bytes;
use log::{debug, warn};

use crate::client::PacketItem;
use crate::rtcp::ReceivedCompoundPacket;
use crate::rtp::{RawPacket, ReceivedPacket};
use crate::{
    ConnectionContext, Error, ErrorInt, PacketContext, PacketContextInner, StreamContext,
    StreamContextInner,
};

use super::{SessionOptions, Timeline, UnknownRtcpSsrcPolicy};

/// Describes how Retina formed its initial expectation for the stream's `ssrc` or `seq`.
#[derive(Copy, Clone, Debug)]
enum InitialExpectation {
    PlayResponseHeader,
    RtpPacket,
    RtcpPacket,
}

#[derive(Copy, Clone)]
struct Ssrc {
    init: InitialExpectation,
    ssrc: u32,
}

impl std::fmt::Debug for Ssrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("Ssrc")
            .field("init", &self.init)
            .field("ssrc", &format_args!("0x{:08x}", self.ssrc))
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
struct Seq {
    init: InitialExpectation,
    next: u16,
}

const REORDER_WINDOW: u16 = 32;

struct BufferedPacket {
    data: Bytes,
    pkt_ctx: PacketContext,
}

struct ReorderBuf {
    slots: Vec<Option<BufferedPacket>>,
    expected_seq: Option<u16>,
    buffered_count: u16,
}

impl ReorderBuf {
    fn new() -> Self {
        let mut slots = Vec::with_capacity(REORDER_WINDOW as usize);
        slots.resize_with(REORDER_WINDOW as usize, || None);
        Self {
            slots,
            expected_seq: None,
            buffered_count: 0,
        }
    }

    /// Insert a packet into the reorder buffer.
    /// Returns true if it was stored, false if it was a duplicate or too old.
    fn insert(&mut self, seq: u16, data: Bytes, pkt_ctx: PacketContext) -> bool {
        let expected = match self.expected_seq {
            Some(e) => e,
            None => {
                self.expected_seq = Some(seq);
                seq
            }
        };

        let ahead = seq.wrapping_sub(expected);
        if ahead >= 0x8000 {
            // Packet is behind expected_seq — too late.
            return false;
        }
        if ahead >= REORDER_WINDOW {
            // Packet is too far ahead; force-advance to make room.
            let skip = ahead - REORDER_WINDOW + 1;
            for _ in 0..skip {
                let idx = self.expected_seq.unwrap() % REORDER_WINDOW;
                if self.slots[idx as usize].take().is_some() {
                    self.buffered_count -= 1;
                }
                self.expected_seq = Some(self.expected_seq.unwrap().wrapping_add(1));
            }
        }

        let idx = (seq % REORDER_WINDOW) as usize;
        if self.slots[idx].is_some() {
            return false; // duplicate
        }
        self.slots[idx] = Some(BufferedPacket { data, pkt_ctx });
        self.buffered_count += 1;
        true
    }

    /// Drain consecutive packets starting from expected_seq.
    /// Returns them in-order.
    fn drain_ready(&mut self) -> Vec<(u16, Bytes, PacketContext)> {
        let mut out = Vec::new();
        let Some(mut seq) = self.expected_seq else {
            return out;
        };
        loop {
            let idx = (seq % REORDER_WINDOW) as usize;
            match self.slots[idx].take() {
                Some(pkt) => {
                    self.buffered_count -= 1;
                    out.push((seq, pkt.data, pkt.pkt_ctx));
                    seq = seq.wrapping_add(1);
                }
                None => break,
            }
        }
        if !out.is_empty() {
            self.expected_seq = Some(seq);
        }
        out
    }
}

/// RTP/RTCP demarshaller which ensures packets have the correct SSRC and
/// monotonically increasing SEQ. Unstable; exposed for benchmark.
///
/// When using UDP, packets are held in a small reorder buffer (~64 KB) and
/// emitted in sequence-number order. When using TCP, they are processed
/// immediately (TCP guarantees ordering).
///
/// This reports packet loss (via [ReceivedPacket::loss]) but doesn't prohibit it
/// of more than `i16::MAX` which would be indistinguishable from non-monotonic sequence numbers.
/// Servers sometimes drop packets internally even when sending data via TCP.
///
/// At least [one camera](https://github.com/scottlamb/moonfire-nvr/wiki/Cameras:-Reolink#reolink-rlc-410-hardware-version-ipc_3816m)
/// sometimes sends data from old RTSP sessions over new ones. This seems like a
/// serious bug, and currently `InorderRtpParser` will error in this case,
/// although it'd be possible to discard the incorrect SSRC instead.
///
/// [RFC 3550 section 8.2](https://tools.ietf.org/html/rfc3550#section-8.2) says that SSRC
/// can change mid-session with a RTCP BYE message. This currently isn't handled. I'm
/// not sure it will ever come up with IP cameras.
#[doc(hidden)] // pub only for the benchmarks; not a stable API.
#[derive(Debug)]
pub struct InorderParser {
    ssrc: Option<Ssrc>,
    seq: Option<Seq>,

    /// Total RTP packets seen in this stream.
    seen_rtp_packets: u64,

    /// Total RTCP packets seen in this stream.
    seen_rtcp_packets: u64,

    unknown_rtcp_session: UnknownRtcpSsrcPolicy,
    seen_unknown_rtcp_session: bool,

    reorder: ReorderBuf,
    ready_queue: VecDeque<PacketItem>,

    reorder_recovered: u64,
}

// ReorderBuf doesn't impl Debug, so we manually impl Debug for InorderParser above
// by adding #[derive(Debug)] and implementing Debug for ReorderBuf:
impl std::fmt::Debug for ReorderBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReorderBuf")
            .field("expected_seq", &self.expected_seq)
            .field("buffered_count", &self.buffered_count)
            .finish()
    }
}

fn note_stale_live555_data_if_tcp(
    tool: Option<&super::Tool>,
    session_options: &SessionOptions,
    conn_ctx: &crate::ConnectionContext,
    stream_ctx: &StreamContext,
    pkt_ctx: &PacketContext,
) {
    if let (
        StreamContext(StreamContextInner::Tcp(stream_ctx)),
        PacketContext(PacketContextInner::Tcp { msg_ctx }),
    ) = (stream_ctx, pkt_ctx)
    {
        super::note_stale_live555_data(
            tool,
            session_options,
            conn_ctx,
            stream_ctx.rtp_channel_id,
            msg_ctx,
        );
    }
}

impl InorderParser {
    pub fn new(
        ssrc: Option<u32>,
        next_seq: Option<u16>,
        unknown_rtcp_session: UnknownRtcpSsrcPolicy,
    ) -> Self {
        Self {
            ssrc: ssrc.map(|ssrc| Ssrc {
                init: InitialExpectation::PlayResponseHeader,
                ssrc,
            }),
            seq: next_seq.map(|next| Seq {
                init: InitialExpectation::PlayResponseHeader,
                next,
            }),
            seen_rtp_packets: 0,
            seen_rtcp_packets: 0,
            unknown_rtcp_session,
            seen_unknown_rtcp_session: false,
            reorder: ReorderBuf::new(),
            ready_queue: VecDeque::new(),
            reorder_recovered: 0,
        }
    }

    /// Returns a previously-buffered packet from the ready queue, if any.
    /// The caller should drain this before polling new UDP data.
    pub fn poll_ready(&mut self) -> Option<PacketItem> {
        self.ready_queue.pop_front()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rtp(
        &mut self,
        session_options: &SessionOptions,
        stream_ctx: &StreamContext,
        tool: Option<&super::Tool>,
        conn_ctx: &ConnectionContext,
        pkt_ctx: &PacketContext,
        timeline: &mut Timeline,
        stream_id: usize,
        data: Bytes,
    ) -> Result<Option<PacketItem>, Error> {
        let is_udp = matches!(stream_ctx.0, StreamContextInner::Udp(..));

        if is_udp {
            return self.rtp_reorder(
                session_options,
                stream_ctx,
                tool,
                conn_ctx,
                pkt_ctx,
                timeline,
                stream_id,
                data,
            );
        }

        // TCP path: process immediately (no reordering needed).
        self.rtp_process(
            session_options,
            stream_ctx,
            tool,
            conn_ctx,
            pkt_ctx,
            timeline,
            stream_id,
            data,
        )
    }

    /// UDP path: buffer the packet, then flush in-order packets.
    #[allow(clippy::too_many_arguments)]
    fn rtp_reorder(
        &mut self,
        session_options: &SessionOptions,
        stream_ctx: &StreamContext,
        tool: Option<&super::Tool>,
        conn_ctx: &ConnectionContext,
        pkt_ctx: &PacketContext,
        timeline: &mut Timeline,
        stream_id: usize,
        data: Bytes,
    ) -> Result<Option<PacketItem>, Error> {
        // Quick-parse header to get seq and ssrc for buffering decisions.
        let (raw, _payload_range) = match RawPacket::new(data.clone()) {
            Ok(r) => r,
            Err(e) => {
                bail!(ErrorInt::PacketError {
                    conn_ctx: *conn_ctx,
                    stream_ctx: stream_ctx.to_owned(),
                    pkt_ctx: *pkt_ctx,
                    stream_id,
                    description: format!(
                        "corrupt RTP header while expecting seq={:?}: {:?}\n{:#?}",
                        &self.seq,
                        e.reason,
                        crate::hex::LimitedHex::new(&e.data[..], 64),
                    ),
                });
            }
        };

        if raw.payload_type() == 50 {
            debug!("skipping pkt with invalid payload type 50");
            return Ok(None);
        }

        let sequence_number = raw.sequence_number();
        let ssrc = raw.ssrc();

        // Validate SSRC (same as original code).
        if matches!(self.ssrc, Some(s) if s.ssrc != ssrc) {
            note_stale_live555_data_if_tcp(tool, session_options, conn_ctx, stream_ctx, pkt_ctx);
            bail!(ErrorInt::RtpPacketError {
                conn_ctx: *conn_ctx,
                pkt_ctx: *pkt_ctx,
                stream_ctx: stream_ctx.to_owned(),
                stream_id,
                ssrc,
                sequence_number,
                description: format!(
                    "wrong ssrc after {} RTP pkts + {} RTCP pkts; expecting ssrc={:?} seq={:?}",
                    self.seen_rtp_packets, self.seen_rtcp_packets, self.ssrc, self.seq,
                ),
            });
        } else if self.ssrc.is_none() {
            self.ssrc = Some(Ssrc {
                init: InitialExpectation::RtpPacket,
                ssrc,
            });
        }

        // Insert into reorder buffer.
        if !self.reorder.insert(sequence_number, data, *pkt_ctx) {
            debug!(
                "reorder: dropping duplicate/late seq={sequence_number} (expected {:?})",
                self.reorder.expected_seq
            );
            return Ok(self.ready_queue.pop_front());
        }

        // Flush consecutive in-order packets from the buffer.
        let ready = self.reorder.drain_ready();
        for (seq, pkt_data, ctx) in ready {
            // Check if this packet was originally out-of-order but now recovered.
            let was_reordered = if let Some(s) = self.seq {
                let expected_loss = seq.wrapping_sub(s.next);
                expected_loss > 0x8000
            } else {
                false
            };
            if was_reordered {
                self.reorder_recovered += 1;
            }

            match self.rtp_process(
                session_options,
                stream_ctx,
                tool,
                conn_ctx,
                &ctx,
                timeline,
                stream_id,
                pkt_data,
            ) {
                Ok(Some(p)) => self.ready_queue.push_back(p),
                Ok(None) => {}
                Err(e) => {
                    warn!("reorder: error processing buffered seq={seq}: {e}");
                }
            }
        }

        Ok(self.ready_queue.pop_front())
    }

    /// Process a single RTP packet through the full pipeline (SSRC check,
    /// loss/ordering check, timeline advance). Used by both TCP (directly)
    /// and UDP (after reorder buffer drains).
    #[allow(clippy::too_many_arguments)]
    fn rtp_process(
        &mut self,
        session_options: &SessionOptions,
        stream_ctx: &StreamContext,
        tool: Option<&super::Tool>,
        conn_ctx: &ConnectionContext,
        pkt_ctx: &PacketContext,
        timeline: &mut Timeline,
        stream_id: usize,
        data: Bytes,
    ) -> Result<Option<PacketItem>, Error> {
        let (raw, payload_range) = RawPacket::new(data).map_err(|e| {
            wrap!(ErrorInt::PacketError {
                conn_ctx: *conn_ctx,
                stream_ctx: stream_ctx.to_owned(),
                pkt_ctx: *pkt_ctx,
                stream_id,
                description: format!(
                    "corrupt RTP header while expecting seq={:?}: {:?}\n{:#?}",
                    &self.seq,
                    e.reason,
                    crate::hex::LimitedHex::new(&e.data[..], 64),
                ),
            })
        })?;

        // Skip pt=50 packets, sent by at least Geovision cameras. I'm not sure
        // what purpose these serve, but they have the same sequence number as
        // the packet immediately before. In TCP streams, this can cause an
        // "Out-of-order packet or large loss" error. In UDP streams, if these
        // are delivered out of order, they will cause the more important other
        // packet with the same sequence number to be skipped.
        if raw.payload_type() == 50 {
            debug!("skipping pkt with invalid payload type 50");
            return Ok(None);
        }

        let sequence_number = raw.sequence_number();
        let ssrc = raw.ssrc();
        let loss =
            sequence_number.wrapping_sub(self.seq.map(|s| s.next).unwrap_or(sequence_number));
        if matches!(self.ssrc, Some(s) if s.ssrc != ssrc) {
            note_stale_live555_data_if_tcp(tool, session_options, conn_ctx, stream_ctx, pkt_ctx);
            bail!(ErrorInt::RtpPacketError {
                conn_ctx: *conn_ctx,
                pkt_ctx: *pkt_ctx,
                stream_ctx: stream_ctx.to_owned(),
                stream_id,
                ssrc,
                sequence_number,
                description: format!(
                    "wrong ssrc after {} RTP pkts + {} RTCP pkts; expecting ssrc={:?} seq={:?}",
                    self.seen_rtp_packets, self.seen_rtcp_packets, self.ssrc, self.seq,
                ),
            });
        } else if self.ssrc.is_none() {
            self.ssrc = Some(Ssrc {
                init: InitialExpectation::RtpPacket,
                ssrc,
            });
        }
        if loss > 0x80_00 {
            if matches!(stream_ctx.0, StreamContextInner::Tcp { .. }) {
                bail!(ErrorInt::RtpPacketError {
                    conn_ctx: *conn_ctx,
                    pkt_ctx: *pkt_ctx,
                    stream_ctx: stream_ctx.to_owned(),
                    stream_id,
                    ssrc,
                    sequence_number,
                    description: format!(
                        "Out-of-order packet or large loss; expecting ssrc={:08x?} seq={:?}",
                        self.ssrc, self.seq
                    ),
                });
            } else {
                // With reorder buffer active this should be rare;
                // the buffer has already been force-drained past this seq.
                debug!(
                    "Skipping out-of-order seq={} when expecting ssrc={:08x?} seq={:?}",
                    sequence_number, self.ssrc, self.seq,
                );
                return Ok(None);
            }
        }
        let timestamp = match timeline.advance_to(raw.timestamp()) {
            Ok(ts) => ts,
            Err(description) => bail!(ErrorInt::RtpPacketError {
                conn_ctx: *conn_ctx,
                pkt_ctx: *pkt_ctx,
                stream_ctx: stream_ctx.to_owned(),
                stream_id,
                ssrc,
                sequence_number,
                description,
            }),
        };
        self.seq = Some(Seq {
            init: self
                .seq
                .map(|s| s.init)
                .unwrap_or(InitialExpectation::RtpPacket),
            next: sequence_number.wrapping_add(1),
        });
        self.seen_rtp_packets += 1;
        Ok(Some(PacketItem::Rtp(ReceivedPacket {
            ctx: *pkt_ctx,
            stream_id,
            timestamp,
            raw,
            payload_range,
            loss,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rtcp(
        &mut self,
        session_options: &SessionOptions,
        stream_ctx: &StreamContext,
        tool: Option<&super::Tool>,
        conn_ctx: &ConnectionContext,
        pkt_ctx: &PacketContext,
        timeline: &mut Timeline,
        stream_id: usize,
        data: Bytes,
    ) -> Result<Option<PacketItem>, String> {
        let first_pkt = crate::rtcp::ReceivedCompoundPacket::validate(&data[..])?;
        let mut rtp_timestamp = None;
        if let Ok(Some(sr)) = first_pkt.as_sender_report() {
            rtp_timestamp = Some(timeline.place(sr.rtp_timestamp()).map_err(
                |mut description| {
                    description.push_str(" in RTCP SR");
                    description
                },
            )?);

            let ssrc = sr.ssrc();
            if matches!(self.ssrc, Some(s) if s.ssrc != ssrc) {
                match self.unknown_rtcp_session {
                    UnknownRtcpSsrcPolicy::AbortSession => {
                        note_stale_live555_data_if_tcp(
                            tool,
                            session_options,
                            conn_ctx,
                            stream_ctx,
                            pkt_ctx,
                        );
                        return Err(format!(
                            "Expected ssrc={:08x?}, got RTCP SR ssrc={:08x}",
                            self.ssrc, ssrc
                        ));
                    }
                    UnknownRtcpSsrcPolicy::Default | UnknownRtcpSsrcPolicy::DropPackets => {
                        if !self.seen_unknown_rtcp_session {
                            warn!(
                                "saw unknown rtcp ssrc {ssrc}; rtp session has ssrc {s:?}",
                                s = self.ssrc
                            );
                            self.seen_unknown_rtcp_session = true;
                        }
                        return Ok(None);
                    }
                    UnknownRtcpSsrcPolicy::ProcessPackets => {}
                }
            } else if self.ssrc.is_none()
                && !matches!(
                    self.unknown_rtcp_session,
                    UnknownRtcpSsrcPolicy::ProcessPackets
                )
            {
                self.ssrc = Some(Ssrc {
                    init: InitialExpectation::RtcpPacket,
                    ssrc,
                });
            }
        }
        self.seen_rtcp_packets += 1;
        Ok(Some(PacketItem::Rtcp(ReceivedCompoundPacket {
            ctx: *pkt_ctx,
            stream_id,
            rtp_timestamp,
            raw: data,
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::client::UdpStreamContext;

    use super::*;

    /// Checks dropping and logging Geovision's extra payload type 50 packets.
    /// On a GV-EBD4701 running V1.02_2021_04_08, these seem to appear after
    /// every IDR frame, with the same sequence number as the final packet in
    /// that frame.
    #[test]
    fn geovision_pt50_packet() {
        let mut timeline = Timeline::new(None, 90_000, None).unwrap();
        let mut parser = InorderParser::new(Some(0xd25614e), None, UnknownRtcpSsrcPolicy::Default);
        let stream_ctx = StreamContext::dummy();

        // Normal packet.
        let (pkt, _payload_range) = crate::rtp::RawPacketBuilder {
            sequence_number: 0x1234,
            timestamp: 141000,
            payload_type: 105,
            ssrc: 0xd25614e,
            mark: true,
        }
        .build(*b"foo")
        .unwrap();
        match parser.rtp(
            &SessionOptions::default(),
            &stream_ctx,
            None,
            &ConnectionContext::dummy(),
            &PacketContext::dummy(),
            &mut timeline,
            0,
            pkt.0,
        ) {
            Ok(Some(PacketItem::Rtp(_))) => {}
            o => panic!("unexpected packet 1 result: {o:#?}"),
        }

        // Mystery pt=50 packet with same sequence number.
        let (pkt, _payload_range) = crate::rtp::RawPacketBuilder {
            sequence_number: 0x1234,
            timestamp: 141000,
            payload_type: 50,
            ssrc: 0xd25614e,
            mark: true,
        }
        .build(*b"bar")
        .unwrap();
        match parser.rtp(
            &SessionOptions::default(),
            &stream_ctx,
            None,
            &ConnectionContext::dummy(),
            &PacketContext::dummy(),
            &mut timeline,
            0,
            pkt.0,
        ) {
            Ok(None) => {}
            o => panic!("unexpected packet 2 result: {o:#?}"),
        }
    }

    #[test]
    fn out_of_order() {
        let mut timeline = Timeline::new(None, 90_000, None).unwrap();
        let mut parser = InorderParser::new(Some(0xd25614e), None, UnknownRtcpSsrcPolicy::Default);
        let stream_ctx = StreamContext(StreamContextInner::Udp(UdpStreamContext {
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_rtp_port: 0,
            peer_rtp_port: 0,
        }));
        let session_options = SessionOptions::default();
        let (pkt, _payload_range) = crate::rtp::RawPacketBuilder {
            sequence_number: 2,
            timestamp: 2,
            payload_type: 96,
            ssrc: 0xd25614e,
            mark: true,
        }
        .build(*b"pkt 2")
        .unwrap();
        match parser.rtp(
            &session_options,
            &stream_ctx,
            None,
            &ConnectionContext::dummy(),
            &PacketContext::dummy(),
            &mut timeline,
            0,
            pkt.0,
        ) {
            Ok(Some(PacketItem::Rtp(p))) => {
                assert_eq!(p.timestamp().elapsed(), 0);
            }
            o => panic!("unexpected packet 2 result: {o:#?}"),
        }

        let (pkt, _payload_range) = crate::rtp::RawPacketBuilder {
            sequence_number: 1,
            timestamp: 1,
            payload_type: 96,
            ssrc: 0xd25614e,
            mark: true,
        }
        .build(*b"pkt 1")
        .unwrap();
        match parser.rtp(
            &session_options,
            &stream_ctx,
            None,
            &ConnectionContext::dummy(),
            &PacketContext::dummy(),
            &mut timeline,
            0,
            pkt.0,
        ) {
            Ok(None) => {}
            o => panic!("unexpected packet 1 result: {o:#?}"),
        }

        let (pkt, _payload_range) = crate::rtp::RawPacketBuilder {
            sequence_number: 3,
            timestamp: 3,
            payload_type: 96,
            ssrc: 0xd25614e,
            mark: true,
        }
        .build(*b"pkt 3")
        .unwrap();
        match parser.rtp(
            &session_options,
            &stream_ctx,
            None,
            &ConnectionContext::dummy(),
            &PacketContext::dummy(),
            &mut timeline,
            0,
            pkt.0,
        ) {
            Ok(Some(PacketItem::Rtp(p))) => {
                // The missing timestamp shouldn't have adjusted time.
                assert_eq!(p.timestamp().elapsed(), 1);
            }
            o => panic!("unexpected packet 2 result: {o:#?}"),
        }
    }

    #[test]
    fn reorder_recovery() {
        let mut timeline = Timeline::new(None, 90_000, None).unwrap();
        let mut parser = InorderParser::new(Some(0xd25614e), None, UnknownRtcpSsrcPolicy::Default);
        let stream_ctx = StreamContext(StreamContextInner::Udp(UdpStreamContext {
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_rtp_port: 0,
            peer_rtp_port: 0,
        }));
        let session_options = SessionOptions::default();

        // Send packets out of order: 10, 12, 11, 13
        let seqs = [10u16, 12, 11, 13];
        let mut results = Vec::new();

        for &seq in &seqs {
            let (pkt, _) = crate::rtp::RawPacketBuilder {
                sequence_number: seq,
                timestamp: seq as u32 * 3000,
                payload_type: 96,
                ssrc: 0xd25614e,
                mark: true,
            }
            .build(vec![seq as u8; 10])
            .unwrap();

            match parser.rtp(
                &session_options,
                &stream_ctx,
                None,
                &ConnectionContext::dummy(),
                &PacketContext::dummy(),
                &mut timeline,
                0,
                pkt.0,
            ) {
                Ok(Some(PacketItem::Rtp(p))) => {
                    results.push(p.raw.sequence_number());
                }
                Ok(None) => {}
                o => panic!("unexpected result for seq={seq}: {o:#?}"),
            }
            // Also drain the ready queue.
            while let Some(PacketItem::Rtp(p)) = parser.poll_ready() {
                results.push(p.raw.sequence_number());
            }
        }

        // All 4 packets should be emitted in order: 10, 11, 12, 13
        assert_eq!(results, vec![10, 11, 12, 13]);
    }
}
