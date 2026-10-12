// Package dkim2 implements the wire format and cryptographic checks in
// draft-ietf-dkim-dkim2-spec-06 (28 August 2026). The draft is work in progress.
//
// Sign adds the initial Message-Instance and DKIM2-Signature fields. Forward
// adds a signature when the signed message content has not changed. Revise
// records a checked Recipe for a modified message. Verify
// validates the complete signature chain and reconstructable message instances.
// A null body Recipe requires explicit opt-in when revising or verifying.
// Verify reports which preceding bodies could not be authenticated.
// A highest-numbered nd= signature requires an out-of-band validator callback.
// DNS keys with t=y produce a None result even if the cryptography succeeds.
// ForwardChecked and ReviseChecked verify incoming messages before adding a
// hop; Forward and Revise only check hashes and custody, not prior DNS keys.
// Verify can call an MTA-owned replay store after authentication. Replay
// storage, delivery policy and DSN handling belong to the MTA.
// This API consumes the complete message in memory.
package dkim2
