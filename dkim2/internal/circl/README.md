# CIRCL ML-DSA-44 source for Go 1.19

This module contains only the source files needed by `sign/mldsa/mldsa44`
from Cloudflare CIRCL v1.6.3. The upstream module declares Go 1.22, while
this subset compiles and passes the DKIM2 tests with Go 1.19.13. Its module
path remains `github.com/cloudflare/circl` so that the DKIM2 API keeps the
same key types. See `LICENSE` for the upstream license.

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
the source and run the DKIM2 tests with Go 1.19 before changing the version in
the root `go.mod`.
