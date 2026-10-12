// Package dkim2 implements the wire format and cryptographic checks in
// draft-ietf-dkim-dkim2-spec-06 (28 August 2026). The draft is work in progress.
//
// Sign adds the initial Message-Instance and DKIM2-Signature fields. Forward
// adds a signature when the signed message content has not changed. Revise
// records a checked Recipe for a modified message. Verify
// validates the complete signature chain and reconstructable message instances.
// A null body Recipe cannot authenticate its preceding body and is rejected.
// Callers must verify an incoming message before changing it or adding a hop;
// Forward and Revise check hashes and custody but do not fetch prior keys.
// Replay databases, delivery policy and DSN handling belong to the MTA.
// This API consumes the complete message in memory.
package dkim2
