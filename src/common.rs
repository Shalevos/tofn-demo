use std::convert::TryInto;

use tofn::{collections::TypedUsize, gg20::keygen::SecretRecoveryKey};

pub mod keygen {
    use tofn::{
        collections::VecMap,
        gg20::keygen::{
            create_party_keypair_and_zksetup_unsafe, new_keygen, KeygenPartyId, KeygenProtocol,
            KeygenShareId,
        },
        sdk::api::PartyShareCounts,
    };

    #[cfg(feature = "malicious")]
    use tofn::gg20::keygen::malicious::Behaviour;

    pub fn initialize_honest_parties(
        party_share_counts: &PartyShareCounts<KeygenPartyId>,
        threshold: usize,
    ) -> VecMap<KeygenShareId, KeygenProtocol> {
        let session_nonce = b"foobar";

        party_share_counts
            .iter()
            .map(|(party_id, &party_share_count)| {
                // each party use the same secret recovery key for all its subshares
                // TODO: generate random recovery key, write to backup file
                let secret_recovery_key = super::dummy_secret_recovery_key(party_id);

                // this generates the Paillier encryption keys with the ZKP proving it is correct.
                // TODO: use create_party_keypair_and_zksetup instead once as a setup and save on the device in the most secure way possible!
                // takes a long time to run in the "safe" version
                let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                    party_id,
                    &secret_recovery_key,
                    session_nonce,
                )
                .unwrap();

                // Now for every share we actually generate the secret share (a random number)
                (0..party_share_count).map(move |subshare_id| {
                    new_keygen(
                        party_share_counts.clone(),
                        threshold,
                        party_id,
                        subshare_id,
                        &party_keygen_data,
                        #[cfg(feature = "malicious")]
                        Behaviour::Honest,
                    )
                    .unwrap()
                })
            })
            .flatten()
            .collect()
    }
}

/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
    let index_bytes = index.as_usize().to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    result[..].try_into().unwrap()
}
