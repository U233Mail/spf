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

// defaultMaxLookup DNS Lookup Limits https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const defaultMaxLookup = 10

func mappingQualifierResult(q Qualifier) Result {
	switch q {
	case QualifierPass:
		return ResultPass
	case QualifierFail:
		return ResultFail
	case QualifierSoftFail:
		return ResultSoftFail
	case QualifierNeutral:
		return ResultNeutral
	default:
		return ResultNone
	}
}

type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

func NewVerifier(sender string, ip net.IP, helloDomain string) *Verifier {
	atIdx := strings.LastIndexByte(sender, '@')
	return &Verifier{
		sender:      sender,
		domain:      sender[atIdx+1:],
		ip:          ip,
		helloDomain: helloDomain,
		resolver:    net.DefaultResolver,
		ctx:         context.TODO(),
		lookups:     0,
	}
}

// Verifier for SPF Version 1
type Verifier struct {
	sender      string
	domain      string // extracted from sender
	ip          net.IP
	helloDomain string

	resolver DNSResolver
	ctx      context.Context

	lookups int // DNS lookup times
}

func (s *Verifier) Test(domain string) (Result, bool, error) {
	// Query DNS for SPF record
	if err := s.increaseLookup(); err != nil {
		return ResultPermError, true, err
	}
	records, err := s.resolver.LookupTXT(s.ctx, domain)
	if err != nil {
		return ResultTempError, true, err
	}

	var redirectHost string

	for _, txt := range records {
		if !strings.HasPrefix(txt, "v=spf1 ") {
			continue
		}
		items := strings.Fields(txt)
		for _, item := range items[1:] {
			item = strings.ToLower(item)

			var qResult Result
			switch Qualifier(item[0]) {
			case QualifierPass, QualifierFail, QualifierNeutral, QualifierSoftFail:
				qResult = mappingQualifierResult(Qualifier(item[0]))
				item = item[1:]
			default:
				qResult = ResultPass
			}

			switch {
			case strings.HasPrefix(item, "redirect="):
				// redirect modifier
				// https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
				redirectHost, err = s.expandMacros(item[8:])
				if err != nil {
					return ResultPermError, true, err
				}
			case strings.HasPrefix(item, "exp="):
				// explanation modifier
				// https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
				// todo: implement
				continue

			case item == "all":
				// mechanism "all"
				// https://datatracker.ietf.org/doc/html/rfc7208#section-5.1
				return qResult, true, nil

			case strings.HasPrefix(item, "include:"):
				// mechanism "include"
				// https://datatracker.ietf.org/doc/html/rfc7208#section-5.2
				host, err := s.expandMacros(item[8:])
				if err != nil {
					return ResultPermError, true, err
				}

				if r, ok, err := s.Test(host); ok {
					switch r {
					case ResultPass:
						return qResult, true, nil
					case ResultPermError, ResultNone:
						return ResultPermError, true, err
					case ResultTempError:
						return ResultTempError, true, err
					default:
						continue
					}
				}

			case strings.HasPrefix(item, "ip4:"), strings.HasPrefix(item, "ip6:"):
				if r, ok, err := s.checkMechanismIP(item, qResult); ok {
					return r, true, err
				}

			case item == "a", strings.HasPrefix(item, "a:"), strings.HasPrefix(item, "a/"):
				if r, ok, err := s.checkMechanismA(item, qResult); ok {
					return r, true, err
				}

			case item == "mx", strings.HasPrefix(item, "mx:"), strings.HasPrefix(item, "mx/"):
				if r, ok, err := s.checkMechanismMX(item, qResult); ok {
					return r, true, err
				}

			case item == "ptr", strings.HasPrefix(item, "ptr:"):
				if r, ok, err := s.checkMechanismPTR(item, qResult); ok {
					return r, true, err
				}
			}
		}

	}

	if redirectHost != "" {
		// "redirect" modifier MUST be ignored
		// when there is an "all" mechanism in the record,
		// regardless of the relative ordering of the terms
		return s.Test(redirectHost)
	}
	return ResultNone, true, nil
}

func (s *Verifier) increaseLookup() error {
	if s.lookups < defaultMaxLookup {
		s.lookups++
		return nil
	}
	return errors.New("DNS lookup limit exceeded")
}

// checkMechanismA processes a mechanism "a"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.3
func (s *Verifier) checkMechanismA(stmt string, r Result) (Result, bool, error) {
	spec := ":" + s.domain
	if len(stmt) > 1 { // && ( stmt[1] == ':' || stmt[1] == '/' )
		spec = stmt[1:]
	}
	host, v4Prefix, v6Prefix, err := s.parseHostDualCIDR(spec)
	if err != nil {
		return ResultPermError, true, fmt.Errorf("parse domain-spec failed(%s): %w", spec, err)
	}

	if err := s.increaseLookup(); err != nil {
		return ResultPermError, true, err
	}
	ips, err := s.resolver.LookupIPAddr(s.ctx, host)
	if err != nil {
		return ResultTempError, true, err
	}

	for _, ip := range ips {
		if s.checkIPDualCIDR(ip.IP, v4Prefix, v6Prefix) {
			return r, true, nil
		}
	}
	return "", false, nil
}

// resolveMechanismMX processes a mechanism "mx"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.4
func (s *Verifier) checkMechanismMX(stmt string, r Result) (Result, bool, error) {
	spec := ":" + s.domain
	if len(stmt) > 2 { // && ( stmt[2] == ':' || stmt[2] == '/' )
		spec = stmt[2:]
	}
	host, v4Prefix, v6Prefix, err := s.parseHostDualCIDR(spec)
	if err != nil {
		return ResultPermError, true, fmt.Errorf("parse domain-spec failed(%s): %w", spec, err)
	}

	if err := s.increaseLookup(); err != nil {
		return ResultPermError, true, err
	}
	hosts, err := s.resolver.LookupMX(s.ctx, host)
	if err != nil {
		return ResultTempError, false, err
	}

	for _, mx := range hosts {
		if err := s.increaseLookup(); err != nil {
			return ResultPermError, true, err
		}
		ips, err := s.resolver.LookupIPAddr(s.ctx, mx.Host)
		if err != nil {
			return ResultTempError, false, err
		}

		for _, ip := range ips {

			if s.checkIPDualCIDR(ip.IP, v4Prefix, v6Prefix) {
				return r, true, nil
			}
		}
	}
	return "", false, nil
}

var regexpHostDualCIDR = regexp.MustCompile("^(:[^/]+)(/[0-9]+)?(//[0-9]+)?$")

// parseHostDualCIDR
// for mx:  "mx" [ ":" domain-spec ] [ dual-cidr-length ]
// for a :  "a"  [ ":" domain-spec ] [ dual-cidr-length ]
func (s *Verifier) parseHostDualCIDR(stmt string) (host string, v4Prefix int, v6Prefix int, err error) {
	matches := regexpHostDualCIDR.FindStringSubmatch(stmt)
	if len(matches) != 4 {
		return "", 0, 0, errors.New("invalid host (dual-cidr) expr")
	}

	host = s.domain
	if matches[1] != "" {
		host, err = s.expandMacros(matches[1][1:])
		if err != nil {
			return "", 0, 0, err
		}
	}

	v4Prefix = net.IPv4len * 8
	if matches[2] != "" {
		v4Prefix, err = strconv.Atoi(strings.TrimPrefix(matches[2], "/"))
		if err != nil || v4Prefix < 0 || v4Prefix > net.IPv4len*8 {
			return "", 0, 0, errors.New("invalid ipv4-cidr-len: " + matches[2])
		}

	}

	v6Prefix = net.IPv6len * 8
	if matches[3] != "" {
		v6Prefix, err = strconv.Atoi(strings.TrimPrefix(matches[3], "//"))
		if err != nil || v6Prefix < 0 || v6Prefix > net.IPv6len*8 {
			return "", 0, 0, errors.New("invalid ipv6-cidr-len: " + matches[3])
		}
	}

	return
}

func (s *Verifier) checkIPDualCIDR(ip net.IP, v4Prefix int, v6Prefix int) bool {
	cidrLen := net.IPv6len * 8
	cidrPfx := v6Prefix
	if ip.To4() != nil {
		cidrLen = net.IPv4len * 8
		cidrPfx = v4Prefix
	}
	cidrNet := net.IPNet{IP: ip, Mask: net.CIDRMask(cidrLen, cidrPfx)}
	return cidrNet.Contains(ip)
}

// checkMechanismPTR processes a mechanism "ptr"
// it's not recommend to use (by rfc7208)
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
func (s *Verifier) checkMechanismPTR(stmt string, r Result) (Result, bool, error) {
	host := s.domain
	if strings.HasPrefix(stmt, "ptr:") {
		host = stmt[4:]
	}
	host, err := s.expandMacros(host)
	if err != nil {
		return ResultPermError, true, err
	}
	if host == "" {
		return ResultPermError, true, errors.New("invalid host in ptr")
	}

	if err := s.increaseLookup(); err != nil {
		return ResultPermError, true, err
	}
	names, err := s.resolver.LookupAddr(s.ctx, s.ip.String())
	if err != nil {
		return ResultTempError, true, err
	}

	for _, name := range names {
		name = strings.ToLower(name)
		if name == host+"." || strings.HasSuffix(name, "."+host+".") {
			return r, true, nil
		}
	}
	return "", false, nil
}

// checkMechanismIP processes a mechanism "ip4" or "ip6"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.6
func (s *Verifier) checkMechanismIP(stmt string, r Result) (Result, bool, error) {
	ipStr := stmt[4:]
	if strings.ContainsRune(ipStr, '/') {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return ResultPermError, true, fmt.Errorf("invalid ipStr address: %s", ipStr)
		}
		if ipNet.Contains(s.ip) {
			return r, true, nil
		}
	} else {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "", false, fmt.Errorf("invalid ipStr address: %s", ipStr)
		}
		if ip.Equal(s.ip) {
			return r, true, nil
		}
	}
	return "", false, nil
}

// checkMechanismExists processes a mechanism "exists"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.7
func (s *Verifier) checkMechanismExists(stmt string, r Result) (Result, bool, error) {
	spec := stmt[7:]
	host, err := s.expandMacros(spec)
	if err != nil {
		return ResultPermError, true, err
	}
	// domain is used for a DNS A RR lookup
	// even when the connection type is IPv6
	ips, err := s.resolver.LookupIP(s.ctx, "ip4", host)
	if err != nil {
		return ResultTempError, true, err
	}
	if len(ips) > 0 {
		return r, true, nil
	}
	return "", false, nil
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
				return "", errors.New("invalid macro expr")
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
				return "", fmt.Errorf("get macro %s failed: %w", macroName, err)
			}
			sb.WriteString(macroVal)
		} else if c == '%' {
			afterPercent = true
		} else {
			sb.WriteRune(c)
		}
	}
	if inMacro || afterPercent {
		return "", errors.New("invalid macro expr")
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
		rs = formatIPDotRepr(s.ip)
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

	// 'c', 'r', 't' allowed in 'exp' only
	// for now we don't support 'exp'
	/*
		case 'c':
				rs = s.ip.String()
		case 'r':
			rs = config.Config.Domain
		case 't':
			rs = strconv.FormatInt(time.Now().Unix(), 10)
	*/
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

func formatIPDotRepr(ip net.IP) string {
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
