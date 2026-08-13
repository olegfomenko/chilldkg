# ChillDKG

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/olegfomenko/chilldkg/issues)
<a href="https://github.com/olegfomenko/chilldkg">
<img src="https://img.shields.io/github/stars/olegfomenko/chilldkg?style=social"/>
</a>

⚠️ __Please note - this crypto library has not been audited, so use it at your own risk.__

---

Experimental Rust implementation of the ChillDKG refers to the
[BlockstreamResearch BIP-FROST-DKG](https://github.com/BlockstreamResearch/bip-frost-dkg).

The crate is built around `k256` secp256k1 scalars and curve points. It exposes
typed participant and coordinator state machines, plus the lower-level crypto
building blocks used by the protocol.

⚠️ This repository is a work in progress.

- [x] The main participant and coordinator DKG flows.
- [x] Tests with reference test vectors.
- [x] Participant recovery using transcript and secret host key.
- [x] Coordinator recovery using transcript.
- [ ] Malicious behavior investigation.
- [ ] Messages serialization.
- [ ] Implementation audit.

## Implementation

- `src/party`: participant state machine.
- `src/coordinator`: coordinator state machine.
- `src/msg.rs`: typed protocol messages and recovery data.
- `src/errors.rs`: ChillDKG-style error names.
- `src/crypto`: tagged hashing, point helpers, encryption pads, proof of possession, and CertEq helpers.
- `tests`: unit tests and reference-vector integration tests.

The API models the protocol as consuming state transitions. Each call to `next`
takes the input for the current step, returns the next state, and returns the
message or output produced by that step.

High-level flow:

1. Each participant creates `ParticipantInitialState`.
2. The coordinator creates `CoordinatorInitialState` from all host public keys
   and threshold `t`.
3. Participants accept the coordinator-provided session parameters plus local
   randomness and produce `ParticipantMsg1`.
4. The coordinator aggregates all `ParticipantMsg1` values into `CoordinatorMsg1`.
5. Participants process `CoordinatorMsg1` and produce `ParticipantMsg2`.
6. The coordinator verifies all `ParticipantMsg2` values and produces
   `CoordinatorMsg2`, coordinator DKG output, and recovery data.
7. Participants verify `CoordinatorMsg2` and produce their final DKG outputs.

### Participant States

```mermaid
stateDiagram-v2
    [*] --> ParticipantInitialState: new(rng)
    ParticipantInitialState --> ParticipantStep1State: next((host_pubkeys, t, random))
    ParticipantInitialState --> Failed: .next() call failed
    ParticipantStep1State --> ParticipantStep2State: next((CoordinatorMsg1, aux_rand))
    ParticipantStep1State --> Failed: .next() call failed
    ParticipantStep2State --> Success: next(CoordinatorMsg2)
    ParticipantStep2State --> Failed: .next() call failed
    Success --> [*]
    Failed --> [*]
```

### Coordinator States

```mermaid
stateDiagram-v2
    [*] --> CoordinatorInitialState: new(host_pubkeys, t)
    CoordinatorInitialState --> CoordinatorStep1State: next([ParticipantMsg1])
    CoordinatorInitialState --> Failed: .next() call failed
    CoordinatorStep1State --> Success: next([ParticipantMsg2])
    CoordinatorStep1State --> Failed: .next() call failed
    Success --> [*]
    Failed --> [*]
```

All transitions return `anyhow::Result`. Validation or protocol failures return
an error instead of advancing to the next state.

## Example

```rust
use chilldkg::coordinator::{CoordinatorInitialState, CoordinatorState};
use chilldkg::msg::{ParticipantMsg1, ParticipantMsg2};
use chilldkg::party::{
    ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
};
use k256::ProjectivePoint;
use rand_core::OsRng;

fn main() -> anyhow::Result<()> {
    const N: usize = 5;
    const T: usize = 3;

    let mut rng = OsRng;


    // 1. Prepare params 

    let participants: Vec<_> = (0..N)
        .map(|_| ParticipantInitialState::new(&mut rng))
        .collect();

    // TODO: Securely save `participants[i].s`

    let host_pubkeys: Vec<ProjectivePoint> =
        participants.iter().map(|p| p.get_host_key()).collect();

    let coordinator = CoordinatorInitialState::new(host_pubkeys.clone(), T)?;

    // 2. Execute step #1

    let mut pmsg1s: Vec<ParticipantMsg1> = Vec::with_capacity(N);
    let participants: Vec<ParticipantStep1State> = participants
        .into_iter()
        .map(|p| {
            let random = [0u8; 32]; // TODO: generate good randomness 
            let (next, msg) = p.next((host_pubkeys.clone(), T, random))?;
            pmsg1s.push(msg);
            Ok(next.unwrap())
        })
        .collect::<anyhow::Result<_>>()?;

    let (coordinator, cmsg1) = coordinator.next(pmsg1s)?;
    let coordinator = coordinator.unwrap();

    // 3. Execute step #2

    let mut pmsg2s: Vec<ParticipantMsg2> = Vec::with_capacity(N);
    let participants: Vec<ParticipantStep2State> = participants
        .into_iter()
        .map(|p| {
            let aux_rand = [1u8; 32];
            let (next, msg) = p.next((cmsg1.clone(), aux_rand))?;
            pmsg2s.push(msg);
            Ok(next.unwrap())
        })
        .collect::<anyhow::Result<_>>()?;

    // Coordinator obtains DKG output immediately. 
    // However, we should wait upon successful execution of the last message by each participant.
    let (_, (cmsg2, coordinator_output, recovery_data)) = coordinator.next(pmsg2s)?;

    // 4. Execute final check

    for participant in participants {
        // Obtain DKG result from each participant.
        let (_, (participant_output, participant_recovery_data)) =
            participant.next(cmsg2.clone())?;

        // TODO: Securely save `participant_output.secshare`

        // Public data should be the same across all participants and coordinator.
        assert_eq!(
            participant_output.threshold_pubkey,
            coordinator_output.threshold_pubkey
        );
        assert_eq!(participant_output.pubshares, coordinator_output.pubshares);
        assert_eq!(participant_recovery_data, recovery_data);
    }

    Ok(())
}
```

In real use, `random` and `aux_rand` must be fresh 32-byte randomness values.
The all-zero arrays above are only to keep the example short.

## Tests

Run all tests:

```bash
cargo test
```

Current vector coverage:

- `participant_step1_vectors`: reference cases `1, 3, 5, 6`.
- `participant_step2_vectors`: reference cases `1, 3, 4, 5, 6, 7`.
- `participant_finalize_vectors`: reference cases `1, 2, 3`.
- `coordinator_step1_vectors`: reference cases `1, 2, 4, 5`.
- `coordinator_finalize_vectors`: reference cases `1, 2, 3`.
- `recover_vectors`: reference cases `1, 2, 3, 4, 5, 6, 7, 8, 9, 11`.

## Differences From The Reference Implementation

This crate follows the protocol logic of the Python reference implementation in
the core successful participant and coordinator DKG flow: VSS coefficient
derivation, EncPedPop encryption pads, PoP verification, CertEq signatures,
Taproot tweaking, public share calculation, and final certificate verification
are intended to match the reference and are checked with reference vectors.

The remaining differences are API, serialization, recovery, and fault-handling
differences:

- The reference public API is byte-oriented, while ours is currently datastructs-oriented.
- The reference messages serialize some group elements with an explicit
  point-at-infinity encoding. This crate currently avoids custom serializers and
  mostly works with typed points plus ordinary compressed SEC1 encoding.
- The reference includes optional malicious-behavior investigation
  (`participant_investigate` and `coordinator_investigate`) for invalid encrypted
  shares. This crate raises the corresponding unknown-fault error during
  participant step 2, but does not carry the investigation data or implement the
  investigation protocol.
- Recovery is split into participant and coordinator APIs in this crate.
- Reference-vector files are adapted only where needed to reach the typed Rust
  API.
- Recovery validation order is not identical. This affects error classification
  for malformed recovery data but not the DKG output accepted on a successful
  recovery.
- Recovery transcript parsing is stricter for public nonces. This may change
  which error is returned for malformed recovery bytes.

## Development Notes

- Uppercase local variable names such as `P_i` and `C_k` denote curve points.
- Lowercase scalar names such as `s`, `r`, and `tweak` denote scalars or ordinary values.
- The implementation deliberately avoids custom serializers for `k256` types for now.
