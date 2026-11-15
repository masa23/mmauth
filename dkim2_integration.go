package mmauth

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/masa23/mmauth/dkim2"
)

const defaultDKIM2MaxMessageBytes int64 = 32 << 20

// ErrDKIM2MessageTooLarge means the opt-in DKIM2 verifier could not retain
// the complete message within its configured memory limit. DKIM and ARC
// processing continues normally.
var ErrDKIM2MessageTooLarge = errors.New("mmauth: DKIM2 message exceeds capture limit")

// MMAuthOptions configures optional verification for one SMTP transaction.
// Zero values leave the existing DKIM and ARC behavior unchanged.
type MMAuthOptions struct {
	EnableDKIM2          bool
	DKIM2Envelope        dkim2.Envelope
	DKIM2VerifyOptions   dkim2.VerifyOptions
	DKIM2MaxMessageBytes int64 // Zero uses a 32 MiB limit.
}

// DKIM2Verification separates a protocol result from a local integration
// error. Checked is false before Verify or if the capture limit was exceeded.
type DKIM2Verification struct {
	Enabled bool
	Checked bool
	Result  dkim2.Result
	Err     error
}

type dkim2Integration struct {
	envelope dkim2.Envelope
	options  dkim2.VerifyOptions
	maxBytes int64
	raw      bytes.Buffer
	overflow bool
	skipped  bool
	once     sync.Once
	state    DKIM2Verification
}

// NewMMAuthWithOptions enables DKIM2 only when EnableDKIM2 is true. The
// envelope must contain the actual SMTP paths, including angle brackets.
// Call Close before Verify, as with NewMMAuth.
func NewMMAuthWithOptions(options MMAuthOptions) (*MMAuth, error) {
	if !options.EnableDKIM2 {
		return newMMAuth(nil), nil
	}
	if options.DKIM2Envelope.MailFrom == "" || len(options.DKIM2Envelope.RcptTo) == 0 {
		return nil, errors.New("mmauth: DKIM2 requires the actual SMTP envelope")
	}
	for _, recipient := range options.DKIM2Envelope.RcptTo {
		if recipient == "" {
			return nil, errors.New("mmauth: DKIM2 requires nonempty RCPT TO paths")
		}
	}
	if options.DKIM2MaxMessageBytes < 0 {
		return nil, errors.New("mmauth: DKIM2 capture limit must not be negative")
	}
	limit := options.DKIM2MaxMessageBytes
	if limit == 0 {
		limit = defaultDKIM2MaxMessageBytes
	}
	envelope := options.DKIM2Envelope
	envelope.RcptTo = append([]string(nil), envelope.RcptTo...)
	return newMMAuth(&dkim2Integration{
		envelope: envelope,
		options:  options.DKIM2VerifyOptions,
		maxBytes: limit,
		state:    DKIM2Verification{Enabled: true},
	}), nil
}

// Write captures the exact bytes read by the existing streaming parser.
// Reaching the DKIM2 limit never interrupts DKIM or ARC processing.
func (d *dkim2Integration) Write(p []byte) (int, error) {
	if d.skipped || d.overflow {
		return len(p), nil
	}
	if int64(len(p)) > d.maxBytes-int64(d.raw.Len()) {
		d.overflow = true
		d.raw = bytes.Buffer{}
		return len(p), nil
	}
	_, _ = d.raw.Write(p)
	return len(p), nil
}

// Unsigned messages need no body capture. Header names are checked before
// DKIM or ARC parsing so an invalid DKIM2 field remains visible to Verify.
func (d *dkim2Integration) skipIfUnsigned(fields headers) {
	for _, field := range fields {
		name, _, ok := strings.Cut(field, ":")
		if ok && (strings.EqualFold(name, "Message-Instance") || strings.EqualFold(name, "DKIM2-Signature")) {
			return
		}
	}
	d.skipped = true
	d.overflow = false
	d.raw = bytes.Buffer{}
}

func (m *MMAuth) verifyDKIM2() {
	if m.dkim2 == nil {
		return
	}
	d := m.dkim2
	d.once.Do(func() {
		defer func() { d.raw = bytes.Buffer{} }()
		if d.skipped {
			d.state.Result = dkim2.Result{Status: dkim2.None}
			d.state.Checked = true
			return
		}
		if d.overflow {
			d.state.Err = fmt.Errorf("%w (%d bytes)", ErrDKIM2MessageTooLarge, d.maxBytes)
			return
		}
		d.state.Result = dkim2.Verify(d.raw.Bytes(), d.envelope, d.options)
		d.state.Checked = true
	})
}

// GetDKIM2Verification reports the opt-in result after Close and Verify.
// A capture error leaves Checked false and does not affect legacy results.
func (m *MMAuth) GetDKIM2Verification() DKIM2Verification {
	if m.dkim2 == nil {
		return DKIM2Verification{}
	}
	state := m.dkim2.state
	state.Result.UnverifiedBodies = append([]int(nil), state.Result.UnverifiedBodies...)
	return state
}

// Authentication-Results comments can contain attacker-controlled paths and
// resolver errors. Keep them short and within RFC 5322 comment syntax.
func dkim2AuthenticationResult(result dkim2.Result) string {
	value := "dkim2=" + string(result.Status)
	if result.Err == nil || result.Status == dkim2.Pass || result.Status == dkim2.None {
		return value
	}
	var comment strings.Builder
	for _, c := range result.Err.Error() {
		if c == '\r' || c == '\n' || c == '\t' {
			c = ' '
		} else if c < 32 || c > 126 {
			c = '?'
		}
		need := 1
		if c == '(' || c == ')' || c == '\\' {
			need++
		}
		if comment.Len()+need > 180 {
			comment.WriteString("...")
			break
		}
		if need == 2 {
			comment.WriteByte('\\')
		}
		comment.WriteByte(byte(c))
	}
	if comment.Len() == 0 {
		return value
	}
	return value + " (" + comment.String() + ")"
}
