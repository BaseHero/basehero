//! Evidence for the attested channel's proof frame.
use bh_confidential_host::QuoteSocket;
use futures_util::future::BoxFuture;
use std::{path::PathBuf, time::Duration};

/// Raw evidence for one handshake: the quote over the handshake's report
/// data, its collateral and the runtime event log.
pub struct Evidence {
    pub quote: Vec<u8>,
    pub collateral: Vec<u8>,
    pub event_log: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestError;
impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("attestation evidence unavailable")
    }
}
impl std::error::Error for AttestError {}

pub trait Attestation: Send + Sync {
    fn evidence(&self, report_data: [u8; 64]) -> BoxFuture<'_, Result<Evidence, AttestError>>;
}

/// The dstack guest agent's quote, and collateral the operator keeps current
/// in a file. Devices verify both offline.
pub struct DstackAttestation {
    socket: QuoteSocket,
    collateral: PathBuf,
    deadline: Duration,
}
impl DstackAttestation {
    pub fn new(socket: PathBuf, collateral: PathBuf, deadline: Duration) -> Self {
        Self {
            socket: QuoteSocket::new(socket),
            collateral,
            deadline,
        }
    }
}
impl Attestation for DstackAttestation {
    fn evidence(&self, report_data: [u8; 64]) -> BoxFuture<'_, Result<Evidence, AttestError>> {
        Box::pin(async move {
            let quote = self
                .socket
                .get_quote_for_report(&report_data, self.deadline)
                .await
                .map_err(|_| AttestError)?;
            let collateral = tokio::fs::read(&self.collateral)
                .await
                .map_err(|_| AttestError)?;
            if collateral.len() > bh_confidential_attestation::MAX_INPUT_BYTES {
                return Err(AttestError);
            }
            Ok(Evidence {
                quote: quote.quote().to_vec(),
                collateral,
                event_log: quote.event_log().to_vec(),
            })
        })
    }
}

/// Local-only: the labelled synthetic quote, which only a device's
/// synthetic appraisal accepts. Not hardware evidence.
#[cfg(feature = "synthetic-attestation")]
pub struct SyntheticAttestation;
#[cfg(feature = "synthetic-attestation")]
impl Attestation for SyntheticAttestation {
    fn evidence(&self, report_data: [u8; 64]) -> BoxFuture<'_, Result<Evidence, AttestError>> {
        Box::pin(async move {
            Ok(Evidence {
                quote: bh_confidential_attestation::synthetic::quote(&report_data),
                collateral: b"synthetic".to_vec(),
                event_log: b"synthetic".to_vec(),
            })
        })
    }
}
