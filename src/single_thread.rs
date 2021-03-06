use std::convert::TryFrom;

use crate::common::keygen;
use ecdsa::{elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint}, hazmat::VerifyPrimitive};
use crate::execute::*;
use k256::{AffinePoint, EncodedPoint};
#[cfg(feature = "malicious")]
use tofn::gg20::sign;
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::{
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{new_sign, MessageDigest, SignParties, SignShareId},
    },
    sdk::api::{PartyShareCounts, Protocol},
};
use tracing::debug;

// use test_env_log::test;
// use tracing_test::traced_test; // enable logs in tests

fn set_up_logs() {
    // set up environment variable for log level
    // set up an event subscriber for logs
    let _ = tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(tracing::Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .try_init();
}
/// A simple test to illustrate use of the library
// #[traced_test]
pub fn basic_correctness() {
    set_up_logs();

    // keygen
    let party_share_counts = PartyShareCounts::from_vec(vec![1, 1, 1, 1, 1]).unwrap(); // 10 total shares
    let threshold = 2; // this is 3/5
    debug!(
        "total_share_count {}, threshold {}, party_count {}",
        party_share_counts.total_share_count(),
        threshold,
        party_share_counts.party_count()
    );

    debug!("keygen...");
    let keygen_shares = keygen::initialize_honest_parties(&party_share_counts, threshold);
    let keygen_share_outputs = execute_protocol(keygen_shares).expect("internal tofn error");
    // This extracts the actual secret shares (private keys) for each share (each party if each one only has 1 share)
    // TODO: where to find the public key
    let secret_key_shares: VecMap<KeygenShareId, SecretKeyShare> =
        keygen_share_outputs.map2(|(keygen_share_id, keygen_share)| match keygen_share {
            Protocol::NotDone(_) => panic!("share_id {} not done yet", keygen_share_id),
            Protocol::Done(result) => result.expect("share finished with error"),
        });
    // TODO: look at this for use with verifying ECDSA https://docs.rs/k256/0.6.0/k256/ecdsa/index.html , https://docs.rs/k256/0.6.0/k256/ecdsa/recoverable/index.html
    // let pubkey_y = secret_key_shares.into_vec()[0].group().y();
    let pubkey_encoded = secret_key_shares.clone().into_vec()[0].group().encoded_pubkey();
    let pubkey_encoded_point = AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(pubkey_encoded).unwrap()).unwrap().to_encoded_point(false);
    let pubkey_bytes = pubkey_encoded_point.as_bytes();
    debug!("pubkey bytes: {:?} {:?}", pubkey_bytes.len(), pubkey_bytes);
    
    // sign
    debug!("sign...");

    // Pick the subset of parties that will participate in the signing of the message (at least threshold parties are needed)
    let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
    for i in 0..(threshold + 1) {
        sign_parties.add(TypedUsize::from_usize(i)).unwrap();
    }

    // Gets the shareids of all the chosen parties (those in the subset)
    let keygen_share_ids = VecMap::<SignShareId, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );

    // The bytes we want to sign
    // This should be the hash of the Tx
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();

    let sign_shares = keygen_share_ids.map(|keygen_share_id| {
        // Here they use a map of all SecretShares to retrieve the secretshare for a given share_id, this would just be taken from the device storage
        let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
        // initiates signing protocol
        new_sign(
            secret_key_share.group(),
            secret_key_share.share(),
            &sign_parties,
            &msg_to_sign,
            #[cfg(feature = "malicious")]
            sign::malicious::Behaviour::Honest,
        )
        .unwrap()
    });

    // Now we just execute from 1 thread the protocol for all parties until it finishes
    let sign_share_outputs = execute_protocol(sign_shares).unwrap();
    // Iterates through the result of each party, making sure they are all done, and get the result signatures (each party has its own copy of the signature - imagine this would be run by each party separately)
    let signatures = sign_share_outputs.map(|output| match output {
        Protocol::NotDone(_) => panic!("sign share not done yet"),
        Protocol::Done(result) => result.expect("sign share finished with error"),
    });

    // grab pubkey bytes from one of the shares
    let pubkey_bytes = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .encoded_pubkey();

    // verify a signature
    let pubkey = k256::AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap(),
    )
    .unwrap();
    let sig = k256::ecdsa::Signature::from_der(signatures.get(TypedUsize::from_usize(0)).unwrap())
        .unwrap();
    assert!(pubkey
        .verify_prehashed(&k256::Scalar::from(&msg_to_sign), &sig)
        .is_ok());
}