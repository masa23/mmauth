# CIRCL ML-DSA-44 source for Go 1.19

This module contains only the source files needed by `sign/mldsa/mldsa44`
from Cloudflare CIRCL v1.6.3. The upstream module declares Go 1.22, while
this subset compiles and passes the DKIM2 tests with Go 1.19.13. Its module
path remains `github.com/cloudflare/circl` so that the DKIM2 API keeps the
same key types. See `LICENSE` for the upstream license.

Keep this copy pinned to v1.6.3. When updating it, verify the source and
run the DKIM2 tests with Go 1.19 before changing the version in the root
`go.mod`.
