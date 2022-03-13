package spf

import (
	"context"
	"net"
	"sync/atomic"
)

type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// defaultMaxLookups is the total number of lookups during SPF evaluation
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const defaultMaxLookups = 10

// LimitResolver is a DNSResolver that limits the number of DNS queries.
// If this limit is exceeded return ResultPermError.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
// todo: implement "void lookups" limit and "timeout" limit
// todo: always returns *CheckException while error is non-nil
type LimitResolver struct {
	resolver DNSResolver
	Limit    int32
}

var limitExceededException = NewCheckError(ResultPermError, "DNS query limit exceeded")

func (r *LimitResolver) increaseLookup() error {
	now := atomic.AddInt32(&r.Limit, -1)
	if now < 0 {
		return limitExceededException
	}
	return nil
}
func (r *LimitResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	return r.resolver.LookupTXT(ctx, name)
}

func (r *LimitResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	return r.resolver.LookupIPAddr(ctx, host)
}

func (r *LimitResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	return r.resolver.LookupIP(ctx, network, host)
}

func (r *LimitResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	return r.resolver.LookupMX(ctx, name)
}

func (r *LimitResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	return r.resolver.LookupAddr(ctx, addr)
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
