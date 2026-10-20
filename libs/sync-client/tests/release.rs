//! A build without the `synthetic-attestation` feature, as every release
//! build is, has no synthetic appraisal: the only appraisal is hardware
//! attestation (see also the crate's compile-fail example).
#![cfg(not(feature = "synthetic-attestation"))]

use bh_sync_client::Appraisal;

#[test]
fn no_synthetic_appraisal_in_default_build() {
    // Exhaustive: this does not compile if another appraisal exists.
    let only = |appraisal: Appraisal| match appraisal {
        Appraisal::Hardware => "hardware",
    };
    assert_eq!(only(Appraisal::Hardware), "hardware");
}
