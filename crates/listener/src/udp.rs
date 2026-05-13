//! UDP transport for the FEC assembler.
//!
//! Binds a UDP socket, parses each datagram as a Solana shred, feeds the assembler.
//! Emits `FecEvent`s on an mpsc channel for downstream consumers.

use crate::{FecAssembler, FecEvent, LeaderResolver};
use std::net::SocketAddr;
use tokio::{net::UdpSocket, sync::mpsc};

/// MAX shred size on mainnet (coding shred = 1228B). We use a generous buffer.
pub const RECV_BUF: usize = 2048;

/// Runs a UDP listener bound to `addr`. Each accepted shred is verified against
/// the leader returned by `resolver` for that shred's slot.
pub async fn run_listener_with_resolver(
    addr: SocketAddr,
    resolver: Box<dyn LeaderResolver>,
) -> std::io::Result<(mpsc::Receiver<FecEvent>, tokio::task::JoinHandle<()>)> {
    let socket = UdpSocket::bind(addr).await?;
    let (tx, rx) = mpsc::channel(1024);
    let handle = tokio::spawn(async move {
        let mut asm = FecAssembler::with_resolver(resolver);
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, _from)) => {
                    for ev in asm.ingest(&buf[..n]) {
                        if tx.send(ev).await.is_err() {
                            return; // consumer dropped
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(FecEvent::Rejected { reason: format!("recv_from: {e}") })
                        .await;
                }
            }
        }
    });
    Ok((rx, handle))
}

/// Compatibility wrapper: single static leader.
pub async fn run_listener(
    addr: SocketAddr,
    leader_pubkey: [u8; 32],
) -> std::io::Result<(mpsc::Receiver<FecEvent>, tokio::task::JoinHandle<()>)> {
    run_listener_with_resolver(addr, Box::new(crate::StaticLeader(leader_pubkey))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FecEvent;
    use ed25519_dalek::SigningKey;
    use lattica_shred::fec_set::{build_fec_set, FecSetParams};

    /// End-to-end loopback test: spawn listener on 127.0.0.1:0, send 32 shreds
    /// via UDP, assert Reconstructed event arrives.
    #[tokio::test]
    async fn e2e_loopback_recovers_block() {
        let signing = SigningKey::from_bytes(&[123u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let payload: Vec<u8> = (0..2_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let fec = build_fec_set(
            &payload,
            FecSetParams {
                slot: 42,
                fec_set_index: 0,
                version: 1,
                parent_offset: 1,
                flags: 0,
                chained_root: [0u8; 32],
                signing_key: &signing,
            },
        )
        .unwrap();

        // Pick an ephemeral port.
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let probe = UdpSocket::bind(bind).await.unwrap();
        let listener_addr = probe.local_addr().unwrap();
        drop(probe);

        let (mut rx, _handle) = run_listener(listener_addr, leader_pk).await.unwrap();

        // Sender socket.
        let send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Deliver 32 data shreds (could be any 32 of 64).
        for i in 0..32 {
            send.send_to(&fec.shreds[i], listener_addr).await.unwrap();
        }

        // Drain events until we see Reconstructed (or timeout).
        let recv = async {
            while let Some(ev) = rx.recv().await {
                if let FecEvent::Reconstructed { merkle_root, das_confidence, .. } = ev {
                    assert_eq!(merkle_root, fec.merkle_root);
                    assert!(das_confidence >= 1.0);
                    return;
                }
            }
            panic!("listener closed before reconstruction");
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), recv)
            .await
            .expect("timed out waiting for reconstruction");
    }
}
