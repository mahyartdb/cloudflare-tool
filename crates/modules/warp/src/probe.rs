//! Tier-1 WARP handshake probe: one WireGuard initiation, one framed response.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use cftool_core::probe::{
    AliveDetail, AliveKind, AttemptRecord, BoxFuture, DeadReason, Probe, ProbeOutcome, ProbeVerdict,
};
use cftool_core::target::{ProbeBudget, ProbeTarget};
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::identity::Identity;
use crate::options::{NoisePreset, noise_datagrams};

pub const INITIATION_SIZE: usize = 148;
pub const RESPONSE_BUFFER_SIZE: usize = 92;

const INDEX: u32 = 1;
const LIGHT_NOISE_DELAY: Duration = Duration::from_millis(2);

pub struct WarpProbe {
    pub identity: Identity,
    pub noise: NoisePreset,
    pub timeout_per_probe: Duration,
}

impl WarpProbe {
    pub fn new(identity: Identity, noise: NoisePreset, timeout_per_probe: Duration) -> Self {
        Self {
            identity,
            noise,
            timeout_per_probe,
        }
    }
}

/// Decodes a standard-alphabet base64 WireGuard key.
pub fn decode_key(value: &str) -> Option<[u8; 32]> {
    STANDARD.decode(value).ok()?.try_into().ok()
}

/// The first sender index boringtun puts on the wire for constructor index `tunn_index`.
///
/// boringtun shifts the constructor index left by 8 and adds 1 before use, so a
/// response's `receiver_idx` echoes this wire value, not the constructor argument.
pub fn derive_wire_index(tunn_index: u32) -> u32 {
    (tunn_index << 8).wrapping_add(1)
}

/// Classifies a datagram by framing and index agreement only.
///
/// `parse_incoming_packet` is parse-only, so an alive verdict proves the reply is
/// framed as a type-2 or type-3 packet aimed at our index; it does not prove AEAD
/// validity. The caller fills `rtt` for live type-2 responses.
pub fn classify_response(bytes: &[u8], our_wire_index: u32) -> Option<ProbeVerdict> {
    if bytes.len() == RESPONSE_BUFFER_SIZE && bytes[0] == 2 {
        let type2 = matches!(
            Tunn::parse_incoming_packet(bytes),
            Ok(Packet::HandshakeResponse(response)) if response.receiver_idx == our_wire_index
        );
        return Some(if type2 {
            ProbeVerdict::Alive {
                rtt: None,
                detail: AliveDetail {
                    kind: AliveKind::Type2Response,
                    facts: Default::default(),
                },
            }
        } else {
            ProbeVerdict::Dead {
                reason: DeadReason::ParseFailure,
            }
        });
    }

    if bytes.len() == 64
        && bytes[0] == 3
        && matches!(
            Tunn::parse_incoming_packet(bytes),
            Ok(Packet::PacketCookieReply(_))
        )
    {
        return Some(ProbeVerdict::Alive {
            rtt: None,
            detail: AliveDetail {
                kind: AliveKind::Cookie,
                facts: Default::default(),
            },
        });
    }

    Some(ProbeVerdict::Dead {
        reason: DeadReason::ParseFailure,
    })
}

impl Probe for WarpProbe {
    fn probe<'a>(
        &'a self,
        target: ProbeTarget,
        budget: ProbeBudget,
    ) -> BoxFuture<'a, ProbeOutcome> {
        Box::pin(async move {
            let started_at = OffsetDateTime::now_utc();

            if budget.cancel.is_cancelled() {
                return dead_outcome(target, started_at, DeadReason::Cancelled);
            }

            let (Some(private_key), Some(public_key)) = (
                decode_key(&self.identity.private_key),
                decode_key(&self.identity.peer_public_key),
            ) else {
                return dead_outcome(target, started_at, DeadReason::Internal);
            };

            let our_wire_index = derive_wire_index(INDEX);
            let initiation = {
                let mut tunn = Tunn::new(
                    StaticSecret::from(private_key),
                    PublicKey::from(public_key),
                    None,
                    None,
                    INDEX,
                    None,
                );
                let mut dst = [0u8; INITIATION_SIZE];
                match tunn.format_handshake_initiation(&mut dst, false) {
                    TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                    _ => return dead_outcome(target, started_at, DeadReason::Internal),
                }
            };

            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => socket,
                Err(_) => return dead_outcome(target, started_at, DeadReason::Unreachable),
            };
            if socket.connect((target.addr, target.port)).await.is_err() {
                return dead_outcome(target, started_at, DeadReason::Unreachable);
            }

            // Type-1 header: prime NAT/conntrack and DPI with a WireGuard-shaped
            // datagram before the real initiation leaves.
            let mut warmup = [0u8; 64];
            warmup[0] = 1;
            if socket.send(&warmup).await.is_err() {
                return dead_outcome(target, started_at, DeadReason::Unreachable);
            }
            if budget.cancel.is_cancelled() {
                return dead_outcome(target, started_at, DeadReason::Cancelled);
            }

            let mut overhead_left = budget.overhead;
            for _ in 0..noise_datagrams(self.noise) {
                let noise_packet = [0x2au8; 64];
                if socket.send(&noise_packet).await.is_err() {
                    return dead_outcome(target, started_at, DeadReason::Unreachable);
                }
                let delay = if overhead_left.is_zero() {
                    LIGHT_NOISE_DELAY
                } else {
                    let share = (overhead_left / 8)
                        .max(Duration::from_millis(1))
                        .min(overhead_left);
                    overhead_left -= share;
                    share
                };
                tokio::select! {
                    _ = budget.cancel.cancelled() => {
                        return dead_outcome(target, started_at, DeadReason::Cancelled);
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }

            let send_at = Instant::now();
            if socket.send(&initiation).await.is_err() {
                return dead_outcome(target, started_at, DeadReason::Unreachable);
            }

            let mut response = [0u8; RESPONSE_BUFFER_SIZE];
            let received = tokio::select! {
                _ = budget.cancel.cancelled() => {
                    return dead_outcome(target, started_at, DeadReason::Cancelled);
                }
                result = timeout(budget.per_attempt_timeout, socket.recv(&mut response)) => result,
            };
            let len = match received {
                Ok(Ok(len)) => len,
                Ok(Err(_)) => return dead_outcome(target, started_at, DeadReason::Unreachable),
                Err(_) => return dead_outcome(target, started_at, DeadReason::Timeout),
            };

            let verdict = match classify_response(&response[..len], our_wire_index) {
                Some(ProbeVerdict::Alive { detail, .. }) => {
                    let rtt = if matches!(&detail.kind, AliveKind::Type2Response) {
                        Some(send_at.elapsed())
                    } else {
                        None
                    };
                    ProbeVerdict::Alive { rtt, detail }
                }
                Some(verdict) => verdict,
                None => ProbeVerdict::Dead {
                    reason: DeadReason::ParseFailure,
                },
            };

            let mut tries_succeeded = 0;
            let mut try_rtts_us = Vec::new();
            if let ProbeVerdict::Alive { rtt, .. } = &verdict {
                tries_succeeded = 1;
                if let Some(rtt) = rtt {
                    try_rtts_us.push(rtt.as_micros() as u32);
                }
            }

            ProbeOutcome {
                target,
                verdict,
                attempts: AttemptRecord {
                    tries_made: 1,
                    tries_succeeded,
                    try_rtts_us,
                },
                started_at,
            }
        })
    }
}

fn dead_outcome(
    target: ProbeTarget,
    started_at: OffsetDateTime,
    reason: DeadReason,
) -> ProbeOutcome {
    ProbeOutcome {
        target,
        verdict: ProbeVerdict::Dead { reason },
        attempts: AttemptRecord {
            tries_made: 1,
            tries_succeeded: 0,
            try_rtts_us: Vec::new(),
        },
        started_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_index_rule() {
        let ours = derive_wire_index(1);

        let mut type2 = [0u8; RESPONSE_BUFFER_SIZE];
        type2[0] = 2;
        type2[4..8].copy_from_slice(&ours.to_le_bytes());
        type2[8..12].copy_from_slice(&ours.to_le_bytes());
        match classify_response(&type2, ours) {
            Some(ProbeVerdict::Alive { rtt, detail }) => {
                assert!(rtt.is_none());
                assert!(matches!(&detail.kind, AliveKind::Type2Response));
            }
            _ => panic!("matching receiver index must classify as alive type-2"),
        }

        type2[8..12].copy_from_slice(&ours.wrapping_add(1).to_le_bytes());
        match classify_response(&type2, ours) {
            Some(ProbeVerdict::Dead { reason, .. }) => {
                assert!(matches!(reason, DeadReason::ParseFailure));
            }
            _ => panic!("foreign receiver index must classify as dead parse failure"),
        }

        let mut type3 = [0u8; 64];
        type3[0] = 3;
        type3[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        match classify_response(&type3, ours) {
            Some(ProbeVerdict::Alive { rtt, detail }) => {
                assert!(rtt.is_none());
                assert!(matches!(&detail.kind, AliveKind::Cookie));
            }
            _ => panic!("type-3 packet must classify as alive cookie"),
        }
    }
}
