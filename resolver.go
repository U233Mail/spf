package spf

import (
	"context"
	"errors"
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
// todo: implement "void lookups" limit
type LimitResolver struct {
	resolver DNSResolver
	Limit    int32
}

var limitExceededAmount = NewCheckError(ResultPermError, "dns: query limit exceeded (amount)")
var limitExceededDeadline = NewCheckError(ResultTempError, "dns: query limit exceeded (deadline)")

func (r *LimitResolver) increaseLookup() error {
	now := atomic.AddInt32(&r.Limit, -1)
	if now < 0 {
		return limitExceededAmount
	}
	return nil
}
func (r *LimitResolver) wrapError(err error) *CheckException {
	if err == nil {
		return nil
	}
	if _, ok := err.(*CheckException); ok {
		return err.(*CheckException)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return limitExceededDeadline
	}
	return WrapCheckError(err, ResultPermError, "dns: unexpected error")
}
func (r *LimitResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	rs, err := r.resolver.LookupTXT(ctx, name)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	rs, err := r.resolver.LookupIPAddr(ctx, host)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	rs, err := r.resolver.LookupIP(ctx, network, host)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
	}
	rs, err := r.resolver.LookupMX(ctx, name)
	return rs, r.wrapError(err)
}

func (r *LimitResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := r.increaseLookup(); err != nil {
		return nil, err
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
