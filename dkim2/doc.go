// Package dkim2 implements the wire format and cryptographic checks in
// draft-ietf-dkim-dkim2-spec-09 (1 November 2026) and
// draft-ietf-dkim-dkim2-dns-03 (2 November 2026). Both are work in progress.
//
// Sign adds the initial Message-Instance and DKIM2-Signature fields. Forward
// adds a signature when the signed message content has not changed. Revise
// records a checked Recipe for a modified message. Verify
// validates the complete signature chain and reconstructable message instances.
// A null body Recipe requires explicit opt-in; Verify reports PERMERROR and
// identifies preceding bodies that could not be authenticated.
// A highest-numbered nd= signature requires an out-of-band validator callback.
// DKIM2 ignores deprecated DNS key tags h=, n=, s= and t=.
// ForwardChecked and ReviseChecked verify incoming messages before adding a
// hop. Forward and Revise require OutOfBandArrangement because they only check
// hashes and custody, not prior DNS keys.
// Verify can call an MTA-owned replay store after authentication. Replay
// storage and delivery policy belong to the MTA.
// VerifyProvisional implements the latest-hop assessment in section 13.2; its
// Pass result does not establish that the entire message is Fully Verified.
// CreateDSN, VerifyDSN and PropagateDSN implement section 16's signed MIME
// reports and receipt-time reconstruction. They return bytes and an envelope;
// the MTA retains receipt metadata, supplies truthful delivery results and
// decides whether to send the report. Null-sender messages never cause DSNs.
// DSNs also support RFC 6533's internationalized status and original-message
// MIME types. Originals containing 8-bit octets use base64-encoded global
// parts, preserving their exact bytes. The MTA must still use SMTPUTF8 when
// the returned envelope or outer message headers require it.
// ReplayCheck runs even for exploded messages; Result.ExplodedAt identifies
// which authenticated signers claim multiple delivery.
// BCC signing requires BCCRecipients metadata and separate SMTP transactions
// for ordinary and blind recipients. Remove populated Bcc/Resent-Bcc fields.
// This API consumes the complete message in memory. It limits messages to
// 32 MiB, headers to 1 MiB, individual fields to 64 KiB and fields to 4096.
// SMTP internationalized domains must be valid IDNA A-labels or U-labels.
package dkim2
