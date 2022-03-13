package spf

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Qualifier for SPF DNS record's directive https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.2
type Qualifier byte

const (
	QualifierPass     Qualifier = '+'
	QualifierFail     Qualifier = '-'
	QualifierSoftFail Qualifier = '~'
	QualifierNeutral  Qualifier = '?'
)

// Result of SPF check https://datatracker.ietf.org/doc/html/rfc7208#section-8
type Result string

const (
	// ResultNone the verifier has no information at all about the authorization
	ResultNone Result = "none"

	// ResultNeutral no definite assertion about the client
	// although a policy for the identity was discovered
	ResultNeutral Result = "neutral"

	// ResultPass the client is authorized
	// to inject mail with the given identity
	ResultPass Result = "pass"

	// ResultFail the client is NOT authorized
	// to use the domain in the given identity
	ResultFail Result = "fail"

	// ResultSoftFail the host is not authorized
	// but is not willing to make a strong policy statement
	ResultSoftFail Result = "softfail"

	// ResultTempError the verifier encountered a transient (generally DNS) error while performing the check
	ResultTempError Result = "temperror"

	// ResultPermError the domain's published records could not be correctly interpreted
	ResultPermError Result = "permerror"
)

// NewVerifier creates a new SPF Verifier
// sender is the email address of the sender (we don't check if it's valid)
// ip is the remote IP address of current connection
// helloDomain is the domain of the SMTP HELO command (only used for %{h} macro)
func NewVerifier(sender string, ip net.IP, helloDomain string) *Verifier {
	atIdx := strings.LastIndexByte(sender, '@')
	s := &Verifier{
		sender:      sender,
		domain:      sender[atIdx+1:],
		ip:          ip,
		helloDomain: helloDomain,
		ctx:         context.TODO(),
		timeout:     defaultSPFTimeout,
		lookups:     0,
	}
	s.SetResolver(net.DefaultResolver)
	return s
}

// Verifier for SPF Version 1
type Verifier struct {
	sender      string
	domain      string // extracted from sender
	ip          net.IP
	helloDomain string

	resolver *LimitResolver
	timeout  time.Duration
	ctx      context.Context

	lookups int // DNS lookup times
}

func (s *Verifier) SetResolver(resolver DNSResolver) {
	limited, ok := resolver.(*LimitResolver)
	if ok {
		s.resolver = limited
	} else {
		s.resolver = NewLimitResolver(resolver, defaultMaxLookups)
	}
}

const defaultSPFTimeout = time.Second * 20

func (s *Verifier) SetTimeout(t time.Duration) {
	s.timeout = t
}

func (s *Verifier) Test(ctx context.Context) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	s.ctx = ctx
	defer cancel()
	return s.checkHost(s.domain)
}

// checkHost checks the SPF record on the given domain
func (s *Verifier) checkHost(domain string) (Result, error) {
	records, err := s.resolver.LookupTXT(s.ctx, domain)
	if err != nil {
		return ResultTempError, err
	}

	var redirectHost string

	for _, txt := range records {
		if !strings.HasPrefix(txt, "v=spf1 ") {
			continue
		}
		items := strings.Fields(txt)
		for _, item := range items[1:] {
			switch {
			case strings.HasPrefix(item, "redirect="):
				// modifier "redirect"
				// https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
				redirectHost, err = s.expandMacros(item[8:])
				if err != nil {
					return ResultPermError, fmt.Errorf("spf: expand macros for %s failed: %w", item[8:], err)
				}
			case strings.HasPrefix(item, "exp="):
				// modifier "exp" (explanation)
				// https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
				continue // ignore, we are not supporting it for now
			default:
				result, matched, err := s.checkMechanism(item)
				if err != nil || matched {
					return result, err
				} // else { continue }
			}
		}

	}

	// If all mechanisms fail to match, and a "redirect" modifier is present
	if redirectHost != "" {
		result, err := s.checkHost(redirectHost)
		// if no SPF record is found, or if the <target-name> is malformed,
		// the result is a "permerror" rather than "none".
		if result == ResultNone {
			return ResultPermError, fmt.Errorf("spf: record not found on redirect host: %s", redirectHost)
		}
		return result, err
	}
	return ResultNone, nil
}

// checkMechanism returns (result, matched, error)
func (s *Verifier) checkMechanism(stmtCS string) (Result, bool, error) {
	stmt := strings.ToLower(stmtCS) // case-insensitive

	var result Result
	switch Qualifier(stmt[0]) {
	case QualifierPass:
		result = ResultPass
		stmt = stmt[1:]
	case QualifierFail:
		result = ResultFail
		stmt = stmt[1:]
	case QualifierSoftFail:
		result = ResultSoftFail
		stmt = stmt[1:]
	case QualifierNeutral:
		result = ResultNeutral
		stmt = stmt[1:]
	default:
		result = ResultPass
	}

	var matched bool
	var exception *CheckException
	switch {
	case stmt == "all":
		// mechanism "all"
		// https://datatracker.ietf.org/doc/html/rfc7208#section-5.1
		return result, true, nil
	case strings.HasPrefix(stmt, "include:"):
		matched, exception = s.checkMechanismInclude(stmtCS)
	case stmt == "a", strings.HasPrefix(stmt, "a:"), strings.HasPrefix(stmt, "a/"):
		matched, exception = s.checkMechanismA(stmtCS)
	case stmt == "mx", strings.HasPrefix(stmt, "mx:"), strings.HasPrefix(stmt, "mx/"):
		matched, exception = s.checkMechanismMX(stmtCS)
	case stmt == "ptr", strings.HasPrefix(stmt, "ptr:"):
		matched, exception = s.checkMechanismPTR(stmtCS)
	case strings.HasPrefix(stmt, "ip4:"), strings.HasPrefix(stmt, "ip6:"):
		matched, exception = s.checkMechanismIP(stmtCS)
	case strings.HasPrefix(stmt, "exists:"):
		matched, exception = s.checkMechanismExists(stmtCS)
	default:
		return ResultPermError, false, fmt.Errorf("spf: unknown mechanism: %s", stmtCS)
	}
	if exception != nil {
		return exception.result, false, exception
	}
	if matched {
		return result, true, nil
	}
	return "", false, nil
}

// checkMechanismInclude processes a mechanism "include"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.2
func (s *Verifier) checkMechanismInclude(stmt string) (bool, *CheckException) {
	host, err := s.expandMacros(stmt[8:])
	if err != nil {
		return false, WrapCheckError(err, ResultPermError, "parse domain-spec failed")
	}

	r, err := s.checkHost(host)
	switch r {
	case ResultPass:
		return true, nil
	case ResultFail, ResultSoftFail, ResultNeutral:
		return false, nil
	case ResultTempError, ResultPermError:
		return false, WrapCheckError(err, r, "check include host failed")
	case ResultNone:
		return false, WrapCheckError(err, ResultPermError, "include host not exists")
	default: // should not happen
		return false, NewCheckError(ResultPermError, "unknown check result")
	}
}

// checkMechanismA processes a mechanism "a".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.3
func (s *Verifier) checkMechanismA(stmt string) (bool, *CheckException) {
	// stmt example: a, a:example.com, a/24, a//64, a:example.com/24//64
	spec := ":" + s.domain
	if len(stmt) > 1 { // && ( stmt[1] == ':' || stmt[1] == '/' )
		spec = stmt[1:]
	}
	host, v4Prefix, v6Prefix, err := s.parseHostDualCIDR(spec)
	if err != nil {
		return false, WrapCheckError(err, ResultPermError, "parse domain-spec failed")
	}

	ips, err := s.resolver.LookupIPAddr(s.ctx, host)
	if err != nil {
		return false, err.(*CheckException)
	}

	for _, ip := range ips {
		if s.checkIPDualCIDR(s.ip, ip.IP, v4Prefix, v6Prefix) {
			return true, nil
		}
	}
	return false, nil
}

// resolveMechanismMX processes a mechanism "mx".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.4
func (s *Verifier) checkMechanismMX(stmt string) (bool, *CheckException) {
	// stmt example: mx, mx:example.com, mx/24, mx//64, mx:example.com/24//64
	spec := ":" + s.domain
	if len(stmt) > 2 { // && ( stmt[2] == ':' || stmt[2] == '/' )
		spec = stmt[2:]
	}
	host, v4Prefix, v6Prefix, err := s.parseHostDualCIDR(spec)
	if err != nil {
		return false, WrapCheckError(err, ResultPermError, "parse domain-spec failed")
	}

	hosts, err := s.resolver.LookupMX(s.ctx, host)
	if err != nil {
		return false, err.(*CheckException)
	}

	for _, mx := range hosts {

		ips, err := s.resolver.LookupIPAddr(s.ctx, mx.Host)
		if err != nil {
			return false, err.(*CheckException)
		}

		for _, ip := range ips {
			if s.checkIPDualCIDR(s.ip, ip.IP, v4Prefix, v6Prefix) {
				return true, nil
			}
		}
	}
	return false, nil
}

var regexpHostDualCIDR = regexp.MustCompile("^(:[^/]+)(/[0-9]+)?(//[0-9]+)?$")

// parseHostDualCIDR
// for mx:  "mx" [ ":" domain-spec ] [ "/" ip4-cidr-length ] [ "//" ip6-cidr-length ]
// for a :  "a"  [ ":" domain-spec ] [ "/" ip4-cidr-length ] [ "//" ip6-cidr-length ]
func (s *Verifier) parseHostDualCIDR(stmt string) (host string, v4Prefix int, v6Prefix int, err error) {
	matches := regexpHostDualCIDR.FindStringSubmatch(stmt)
	if len(matches) != 4 {
		return "", 0, 0, errors.New("invalid host or dual-cidr expression")
	}

	host = s.domain
	if matches[1] != "" {
		host, err = s.expandMacros(matches[1][1:])
		if err != nil {
			return "", 0, 0, err
		}
	}

	v4Prefix = net.IPv4len * 8 // default single ip, /32
	if matches[2] != "" {
		v4Prefix, err = strconv.Atoi(strings.TrimPrefix(matches[2], "/"))
		if err != nil || v4Prefix < 0 || v4Prefix > net.IPv4len*8 {
			return "", 0, 0, errors.New("invalid ipv4-cidr-len: " + matches[2])
		}

	}

	v6Prefix = net.IPv6len * 8 // default  single ip, /128
	if matches[3] != "" {
		v6Prefix, err = strconv.Atoi(strings.TrimPrefix(matches[3], "//"))
		if err != nil || v6Prefix < 0 || v6Prefix > net.IPv6len*8 {
			return "", 0, 0, errors.New("invalid ipv6-cidr-len: " + matches[3])
		}
	}

	return
}

func (s *Verifier) checkIPDualCIDR(target, ipNet net.IP, v4Prefix int, v6Prefix int) bool {
	cidrLen := net.IPv6len * 8
	cidrPfx := v6Prefix
	if ipNet.To4() != nil {
		cidrLen = net.IPv4len * 8
		cidrPfx = v4Prefix
	}
	cidrNet := net.IPNet{IP: ipNet, Mask: net.CIDRMask(cidrLen, cidrPfx)}
	return cidrNet.Contains(target)
}

// checkMechanismPTR processes a mechanism "ptr".
// It's not recommend to use.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
func (s *Verifier) checkMechanismPTR(stmt string) (bool, *CheckException) {
	// stmt example: ptr, ptr:example.com
	host := s.domain
	if strings.HasPrefix(stmt, "ptr:") {
		host = stmt[4:]
	}
	host, err := s.expandMacros(host)
	if err != nil {
		return false, WrapCheckError(err, ResultPermError, "parse domain-spec failed")
	}
	if host == "" {
		return false, NewCheckError(ResultPermError, "invalid empty host in ptr")
	}

	names, err := s.resolver.LookupAddr(s.ctx, s.ip.String())
	if err != nil {
		return false, err.(*CheckException)
	}

	for _, name := range names {
		name = strings.ToLower(name)
		if name == host+"." || strings.HasSuffix(name, "."+host+".") {
			return true, nil
		}
	}
	return false, nil
}

// checkMechanismIP processes a mechanism "ip4" or "ip6".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.6
func (s *Verifier) checkMechanismIP(stmt string) (bool, *CheckException) {
	// stmt example: ip4:192.168.0.1, ip6:2001:db8::, ip4:192.168.0.1/24, ip6:2001:db8::/32
	ipStr := stmt[4:]
	if strings.ContainsRune(ipStr, '/') {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return false, NewCheckError(ResultPermError, "invalid CIDR: "+ipStr)
		}
		if ipNet.Contains(s.ip) {
			return true, nil
		}
	} else {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false, NewCheckError(ResultPermError, "invalid IP: "+ipStr)
		}
		if ip.Equal(s.ip) {
			return true, nil
		}
	}
	return false, nil
}

// checkMechanismExists processes a mechanism "exists"
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.7
func (s *Verifier) checkMechanismExists(stmt string) (bool, *CheckException) {
	// stmt example: "exists:example.com", "exists:%{ir}.%{l1r+}.%{d}"
	spec := stmt[7:]
	host, err := s.expandMacros(spec)
	if err != nil {
		return false, WrapCheckError(err, ResultPermError, "parse domain-spec failed")
	}
	// domain is used for a DNS A RR lookup
	// (even when the connection type is IPv6)
	ips, err := s.resolver.LookupIP(s.ctx, "ip4", host)
	if err != nil {
		return false, err.(*CheckException)
	}
	if len(ips) > 0 {
		return true, nil
	}
	return false, nil
}

// expandMacros expand domain-spec to hostname
// Reference: https://datatracker.ietf.org/doc/html/rfc7208#section-7
func (s *Verifier) expandMacros(stmt string) (string, error) {
	afterPercent := false
	inMacro := false
	var macroName string
	var sb strings.Builder
	var err error

	for _, c := range stmt {
		if afterPercent {
			switch c {
			case '%':
				sb.WriteRune('%')
			case '_':
				sb.WriteRune(' ')
			case '-':
				sb.WriteString("%20")
			case '{':
				inMacro = true
				macroName = ""
			default:
				return "", errors.New("invalid macro expression")
			}
			afterPercent = false
		} else if inMacro {
			if c != '}' {
				macroName += string(c)
				continue
			}
			inMacro = false
			var macroVal string
			if macroVal, err = s.getMacroValue(macroName); err != nil {
				return "", fmt.Errorf("get value for macro %s failed: %w", macroName, err)
			}
			sb.WriteString(macroVal)
		} else if c == '%' {
			afterPercent = true
		} else {
			sb.WriteRune(c)
		}
	}
	if inMacro || afterPercent {
		return "", errors.New("invalid macro expression")
	}
	return sb.String(), nil

}

var regexpMacroModifier = regexp.MustCompile(`^([0-9]*)(r)?([.\-+,/_=]+)?$`)
var errInvalidMacro = errors.New("invalid macro")

func (s *Verifier) getMacroValue(name string) (rs string, err error) {
	if len(name) == 0 {
		return "", errInvalidMacro
	}

	switch name[0] {
	case 's':
		rs = s.sender
	case 'l':
		atIdx := strings.LastIndexByte(s.sender, '@')
		rs = s.sender[:atIdx]
	case 'o', 'd':
		rs = s.domain
	case 'i':
		rs = formatIPDotNotation(s.ip)
	case 'p':
		// do not use, always return safe value
		// https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
		rs = "unknown"
	case 'v':
		if s.ip.To4() != nil {
			rs = "in-addr"
		} else {
			rs = "ip6"
		}
	case 'h':
		rs = s.helloDomain

	default:
		return "", errInvalidMacro
	}

	matches := regexpMacroModifier.FindStringSubmatch(name[1:])
	if len(matches) != 4 {
		return "", errInvalidMacro
	}

	if matches[1] != "" || matches[2] != "" || matches[3] != "" {
		delimiter := "."
		if matches[3] != "" {
			delimiter = matches[3]
		}
		items := strings.FieldsFunc(rs, func(r rune) bool {
			for _, d := range delimiter {
				if r == d {
					return true
				}
			}
			return false
		})

		if matches[2] != "" {
			reverseStringSlice(items)
		}
		if matches[1] != "" {
			amount, _ := strconv.Atoi(matches[1])
			if amount < len(items) {
				items = items[len(items)-amount:]
			}
		}
		rs = strings.Join(items, ".")

	}
	return
}

func reverseStringSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func formatIPDotNotation(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}

	// For IPv6 addresses, the "i" macro expands to a dot-format address
	// https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
	buf := make([]byte, net.IPv6len*2)
	hex.Encode(buf, ip)

	var sb strings.Builder
	sb.Grow(64)
	for _, c := range buf {
		sb.WriteByte(c)
		sb.WriteByte('.')
	}
	return sb.String()[:63]
}
