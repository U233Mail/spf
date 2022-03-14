package spf

import (
	"net"
	"reflect"
	"testing"

	"github.com/foxcpp/go-mockdns"
)

func Test_reverseStringSlice(t *testing.T) {

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			"Odd",
			[]string{"a", "b", "c"},
			[]string{"c", "b", "a"},
		},
		{
			"Even",
			[]string{"1", "2", "3", "4"},
			[]string{"4", "3", "2", "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reverseStringSlice(tt.input)
			if !reflect.DeepEqual(tt.input, tt.want) {
				t.Errorf("reverseStringSlice(%v) = %v, want %v", tt.input, tt.input, tt.want)
			}
		})
	}
}

func Test_formatIPDotNotation(t *testing.T) {
	tests := []struct {
		name  string
		input net.IP
		want  string
	}{
		{"IPv4", net.ParseIP("192.0.2.1"), "192.0.2.1"},
		{
			"IPv6",
			net.ParseIP("2001:db8::1"),
			"2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatIPDotNotation(tt.input); got != tt.want {
				t.Errorf("formatIPDotNotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_getMacroValue(t *testing.T) {
	s := NewVerifier(
		"strong-bad@email.example.com",
		net.ParseIP("192.0.2.3"),
		"another.example.com",
	)

	tests := []struct {
		input   string
		wantRs  string
		wantErr bool
	}{
		// https://datatracker.ietf.org/doc/html/rfc7208#section-7.4
		{"s", "strong-bad@email.example.com", false},
		{"o", "email.example.com", false},
		{"d", "email.example.com", false},
		{"d4", "email.example.com", false},
		{"d3", "email.example.com", false},
		{"d2", "example.com", false},
		{"d1", "com", false},
		{"dr", "com.example.email", false},
		{"d2r", "example.email", false},
		{"l", "strong-bad", false},
		{"l-", "strong.bad", false},
		{"lr", "strong-bad", false},
		{"lr-", "bad.strong", false},
		{"l1r-", "strong", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {

			gotRs, err := s.getMacroValue(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMacroValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRs != tt.wantRs {
				t.Errorf("getMacroValue() gotRs = %v, want %v", gotRs, tt.wantRs)
			}
		})
	}
}

func TestVerifier_expandMacros(t *testing.T) {
	v4 := NewVerifier(
		"strong-bad@email.example.com",
		net.ParseIP("192.0.2.3"),
		"another.example.com",
	)
	v6 := NewVerifier(
		"strong-bad@email.example.com",
		net.ParseIP("2001:db8::cb01"),
		"another.example.com",
	)
	tests := []struct {
		inst    *Verifier
		input   string
		want    string
		wantErr bool
	}{
		// https://datatracker.ietf.org/doc/html/rfc7208#section-7.4
		{v4, "%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com", false},
		{v4, "%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com", false},
		{v4, "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com", false},
		{v4, "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com", false},
		{v4, "%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net", false},
		{
			v6,
			"%{ir}.%{v}._spf.%{d2}",
			"1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
			false,
		},

		{v4, "%{ir}.%{l1r+-}._spf.%{d}", "3.2.0.192.strong._spf.email.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {

			got, err := tt.inst.expandMacros(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandMacros() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("expandMacros() got = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestVerifier_checkMechanismMX(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			MX: []net.MX{{Host: "mx.example.com", Pref: 5}},
		},
		"mail.example.com.": {
			MX: []net.MX{{Host: "mx.example.com", Pref: 5}},
		},

		"mx.example.com.": {
			A:    []string{"10.10.10.10"},
			AAAA: []string{"2001:db8::1"},
		},
	}}
	cases := []struct {
		stmt        string
		sender      string
		ip          string
		helloDomain string
		want        bool
		wantErr     bool
	}{
		{"mx", "test@example.com", "10.10.10.10", "example.net", true, false},
		{"mx/24", "test@example.com", "10.10.10.254", "example.net", true, false},
		{"mx:mail.example.com", "test@example.com", "10.10.10.10", "example.net", true, false},
		{"mx:mail.example.com/24", "test@example.com", "10.10.10.254", "example.net", true, false},

		{"mx", "test@example.com", "2001:db8::1", "example.net", true, false},
		{"mx//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},
		{"mx:mail.example.com//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},
		{"mx:mail.example.com/24//64", "test@example.com", "10.10.10.254", "example.net", true, false},
		{"mx:mail.example.com/24//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},

		{"mx", "test@example.com", "192.168.1.1", "example.net", false, false},
		{"mx:non-exist.example.com", "test@example.com", "10.10.10.10", "example.net", false, true},
	}
	for _, tt := range cases {
		t.Run(tt.stmt, func(t *testing.T) {
			s := NewVerifier(tt.sender, net.ParseIP(tt.ip), tt.helloDomain)
			s.SetResolver(resolver)
			matched, err := s.checkMechanismMX(tt.stmt)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMechanismMX() err = %v, want = %v", err, tt.wantErr)
			}
			if matched != tt.want {
				t.Errorf("checkMechanismMX() matched = %v, want = %v", matched, tt.want)
			}
		})
	}

}
