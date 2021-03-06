package spf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/miekg/dns"
)

type DNSResolver interface {
	// LookupTXT returns all TXT records for the given domain.
	LookupTXT(ctx context.Context, name string) ([]string, error)

	// LookupNetIP returns all IP addresses of the given host.
	// If network is "ip", IPv6 and IPv4 addresses are returned.
	// If network is "ip4", only IPv4 addresses are returned.
	// If network is "ip6", only IPv6 addresses are returned.
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)

	// LookupMX returns all MX records (host and priority) for a domain.
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)

	// LookupAddr returns the PTR records (domain) for an IP address.
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// defaultMaxLookups is the total number of lookups during SPF evaluation
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const defaultMaxLookups = 10

// LimitResolver is a DNSResolver that limits the number of DNS queries.
// If this limit is exceeded return ResultPermError.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
// todo: implement "void lookups" limit
type LimitResolver struct {
	resolver DNSResolver
	Limit    int32
}

var limitExceededAmount = NewCheckError(ResultPermError, "dns: query limit exceeded (amount)")
var limitExceededDeadline = NewCheckError(ResultTempError, "dns: query limit exceeded (deadline)")

func (r *LimitResolver) increaseLookup(times int32) error {
	now := atomic.AddInt32(&r.Limit, -times)
	if now < 0 {
		return limitExceededAmount
	}
	return nil
}

func (r *LimitResolver) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*CheckError); ok {
		return err.(*CheckError)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return limitExceededDeadline
	}
	dnsErr := new(net.DNSError)
	if errors.As(err, &dnsErr) {
		if dnsErr.Temporary() {
			return NewCheckError(ResultTempError, "dns: "+dnsErr.Error())
		}
		if dnsErr.IsNotFound {
			return NewCheckError(ResultNone, "dns: "+dnsErr.Error())
		}
	}
	return WrapCheckError(err, ResultPermError, "dns: unexpected error")
}
func (r *LimitResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := r.increaseLookup(1); err != nil {
		return nil, err
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, NewCheckError(ResultPermError, "dns: invalid domain name")
	}
	rs, err := r.resolver.LookupTXT(ctx, name)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	lookupTimes := int32(1)
	if network == "ip" { // "ip" means both IPv4(A) and IPv6(AAAA)
		lookupTimes = 2
	}
	if err := r.increaseLookup(lookupTimes); err != nil {
		return nil, err
	}
	if _, ok := dns.IsDomainName(host); !ok {
		return nil, NewCheckError(ResultPermError, "dns: invalid domain name")
	}
	rs, err := r.resolver.LookupNetIP(ctx, network, host)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := r.increaseLookup(1); err != nil {
		return nil, err
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, NewCheckError(ResultPermError, "dns: invalid domain name")
	}
	rs, err := r.resolver.LookupMX(ctx, name)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := r.increaseLookup(1); err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return nil, NewCheckError(ResultPermError, "dns: invalid IP address")
	}
	rs, err := r.resolver.LookupAddr(ctx, addr)
	return rs, r.wrapError(err)
}

func NewLimitResolver(dns DNSResolver, limit int) *LimitResolver {
	if limit <= 0 {
		limit = defaultMaxLookups
	}
	return &LimitResolver{
		resolver: dns,
		Limit:    int32(limit),
	}
}
