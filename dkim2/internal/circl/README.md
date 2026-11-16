# CIRCL ML-DSA-44 source for Go 1.19

This directory contains only the source files needed by `sign/mldsa/mldsa44`
from Cloudflare CIRCL v1.6.3. The upstream module declares Go 1.22, while
this subset compiles and passes the DKIM2 tests with Go 1.19.13. It belongs
to the mmauth module, with imports relocated beneath
`github.com/masa23/mmauth/dkim2/internal/circl`. There is no nested module
or consumer-side replacement: the sources and local fixes are included in
the published mmauth module itself. See `LICENSE` for the upstream license.

Consumers obtain keys through the public
`github.com/masa23/mmauth/dkim2/mldsa44` facade. Its key types provide binary
serialization methods, and its private keys implement `crypto.Signer` for
`dkim2.SignOptions.Key`.

The ML-DSA-44 public-key `tr` cache is stored by value, backporting
[upstream PR #606](https://github.com/cloudflare/circl/pull/606)
(merge commit `cedd4ed`, included in v1.6.4). This prevents later private-key
`Unpack` calls from changing the hash cached in an already returned public key.
In addition to the upstream backport, this local copy also copies the public
key's `A` matrix cache in `Public` and `NewKeyFromSeed`. Otherwise unpacking
a different private key into the same object would still modify an already
returned public key through that shared matrix. `TestPublicTrIsIndependentOfPrivate`
and `TestPublicMatrixIsIndependentOfPrivate` cover both public-key constructors.

Keep this copy based on v1.6.3 with the changes above. When updating it, verify
the source and run the DKIM2 tests and an external-consumer build with Go 1.19.
