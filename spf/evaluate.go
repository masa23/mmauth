package spf

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func (r *Record) Evaluate(ip net.IP, domain, sender, helo string, now time.Time, resv SPFResolver, depth int) *Result {
	if depth > 10 {
		return &Result{Status: PermError, Reason: "include/redirect depth exceeded"}
	}

	// 1) mechanisms
	res := r.evaluateMechanisms(ip, domain, sender, helo, now, resv, depth)

	// 2) redirect modifier
	res = r.handleRedirectModifier(res, ip, domain, sender, helo, now, resv, depth)

	// 3) 何もマッチしなければ Neutral (RFC 7208 4.7/1)
	return res
}

func (r *Record) evaluateMechanisms(ip net.IP, domain, sender, helo string, now time.Time, resv SPFResolver, depth int) *Result {
	var last *Result

	for _, me := range r.Mechanisms {
		match, mres := r.matchMechanism(me, ip, domain, sender, helo, now, resv, depth)
		if mres != nil { // Temp/Perm error
			return mres
		}
		if match {
			result := &Result{
				Status: qualToStatus(me.Qualifier),
				Reason: fmt.Sprintf("matched %s", me.Mechanism),
			}

			// exp= modifier (fail時のみ)
			var expErr *Result
			result, expErr = r.handleExpModifier(result, ip, domain, sender, helo, now, resv)
			if expErr != nil {
				return expErr
			}

			return result
		}

		last = mres
		_ = last
	}

	// すべてマッチしなければ Neutral (この時点では redirect をまだ見ない)
	res := &Result{Status: Neutral, Reason: "no mechanism matched"}
	return res
}

func (r *Record) handleExpModifier(result *Result, ip net.IP, domain, sender, helo string, now time.Time, resv SPFResolver) (*Result, *Result) {
	if result == nil || result.Status != Fail {
		return result, nil
	}

	if r.Exp == "" {
		result.Reason = "DEFAULT"
		return result, nil
	}

	// exp=の値が空白のみの場合は PermError (RFC 7208 6.2/4)
	// If the exp= value consists only of whitespace, it is a PermError (RFC 7208 6.2/4)
	if strings.TrimSpace(r.Exp) == "" {
		return nil, &Result{Status: PermError, Reason: "exp= domain-spec is empty"}
	}

	if res := incrementDNSMechanismCounter(resv); res != nil {
		return nil, res
	}

	ctx := MacroContext{
		IP:          ip,
		Domain:      domain,
		Sender:      sender,
		Helo:        helo,
		Receiver:    domain,
		Now:         now,
		DNSResolver: resv,
	}

	expandedExp, err := resv.ReplaceMacroValues(r.Exp, ctx, MacroPurposeExp)
	if err != nil {
		// exp macro expansion error ignored
		return result, nil
	}

	// RFC 7208 8.1: マクロ展開後のドメイン名が253文字を超える場合は左側を切り捨てる
	// RFC 7208 8.1: If the domain name after macro expansion exceeds 253 characters, truncate the left side
	if len(expandedExp) > 253 {
		labels := strings.Split(expandedExp, ".")
		// 右側のラベルを保持するように修正
		// Modified to preserve labels on the right side
		for len(strings.Join(labels, ".")) > 253 {
			if len(labels) <= 1 {
				// すべてのラベルを削除しても253文字を超える場合は、最後の253文字を返す
				// If removing all labels still exceeds 253 characters, return the last 253 characters
				expandedExp = expandedExp[len(expandedExp)-253:]
				break
			}
			// 左側のラベルを削除
			// Remove labels from the left side
			labels = labels[1:]
		}
		expandedExp = strings.Join(labels, ".")
	}

	expRecords, expRes := resv.lookupTXT(expandedExp)
	if expRes != nil {
		// exp TXT lookup error ignored (RFC 7208 6.2/4)
		result.Reason = "DEFAULT"
		return result, nil
	}

	if len(expRecords) == 0 || len(expRecords) > 1 {
		result.Reason = "DEFAULT"
		return result, nil
	}

	expandedReason, err := resv.ReplaceMacroValues(expRecords[0], ctx, MacroPurposeExp)
	if err != nil {
		// If macro expansion resulted in an error, use the default explanation
		// This handles cases like invalid macro syntax (e.g., %{x})
		result.Reason = "DEFAULT"
		return result, nil
	}

	// Check for non-ASCII characters in the explanation (RFC 7208 6.2/5)
	for _, r := range expandedReason {
		if r > 127 {
			// Non-ASCII character found, use default explanation
			result.Reason = "DEFAULT"
			return result, nil
		}
	}

	// Check for syntax errors in the explanation text (RFC 7208 6.2/4)
	// Specifically, look for invalid macro syntax like %{x}
	// A simple check for %{ followed by a single character and } is sufficient for common cases
	// More complex validation could be added if needed
	if strings.Contains(expandedReason, "%{") {
		// Iterate through the string to find invalid macro patterns
		for i := 0; i < len(expandedReason)-2; i++ {
			if expandedReason[i] == '%' && expandedReason[i+1] == '{' {
				// Found a potential macro start
				// Check if it's followed by a single character and then '}'
				// This is a simplified check for common syntax errors
				if i+3 < len(expandedReason) && expandedReason[i+3] == '}' {
					// This looks like an invalid macro like %{x}
					// Use default explanation
					result.Reason = "DEFAULT"
					return result, nil
				}
			}
		}
	}

	result.Reason = expandedReason
	return result, nil
}

func (r *Record) handleRedirectModifier(current *Result, ip net.IP, domain, sender, helo string, now time.Time, resv SPFResolver, depth int) *Result {
	if depth > 10 {
		return &Result{Status: PermError, Reason: "include/redirect depth exceeded"}
	}

	redir := r.getModifier(ModifierRedirect)
	if redir == "" {
		return current
	}

	// RFC 7208: レコード内にallがある場合、redirectは無視する
	if r.AllExists {
		return current
	}

	if res := incrementDNSMechanismCounter(resv); res != nil {
		return res
	}

	ctx := MacroContext{
		IP:          ip,
		Domain:      domain,
		Sender:      sender,
		Helo:        helo,
		Now:         now,
		DNSResolver: resv,
	}

	expandedRedir, res := expandDomainSpec(redir, ctx, MacroPurposeDomainSpec)
	if res != nil {
		return res
	}

	// 循環参照のチェック
	if resv.isVisited(expandedRedir) {
		return &Result{Status: PermError, Reason: "circular reference detected in redirect"}
	}

	// 訪問済みドメインの記録
	resv.markVisited(expandedRedir)
	defer resv.unmarkVisited(expandedRedir)

	rec, res := resv.lookupRecord(expandedRedir)
	if res != nil {
		if res.Status == None {
			return &Result{Status: PermError, Reason: "redirect domain has no SPF record"}
		}
		return res
	}

	return rec.Evaluate(ip, expandedRedir, sender, helo, now, resv, depth+1)
}

func qualToStatus(q Qualifier) Status {
	switch q {
	case QualifierFail:
		return Fail
	case QualifierSoftFail:
		return SoftFail
	case QualifierNeutral:
		return Neutral
	default:
		return Pass
	}
}
