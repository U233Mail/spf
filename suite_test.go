package spf

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/foxcpp/go-mockdns"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type testSuite struct {
	Description string                    `yaml:"description"`
	Tests       map[string]testCase       `yaml:"tests"`
	ZoneData    map[string]testZoneRecord `yaml:"zonedata"`
}

type testCase struct {
	Description string     `yaml:"description"`
	Comment     string     `yaml:"comment"`
	Spec        string     `yaml:"spec"`
	Helo        string     `yaml:"helo"`
	Host        string     `yaml:"host"`
	MailFrom    string     `yaml:"mailfrom"`
	Result      testResult `yaml:"result"`
	Explanation string     `yaml:"explanation"`
}
type testResult []Result

func (t *testResult) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var singleVal Result
	if err := unmarshal(&singleVal); err == nil {
		*t = []Result{singleVal}
		return nil
	}
	var multipleVal []Result
	if err := unmarshal(&multipleVal); err == nil {
		*t = multipleVal
		return nil
	}
	return fmt.Errorf("unable to unmarshal test result")
}

type testZoneRecord mockdns.Zone

func (t *testZoneRecord) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var items []interface{}
	if err := unmarshal(&items); err != nil {
		return err
	}
	for _, item := range items {
		switch item.(type) {
		case string:
			if item.(string) == "TIMEOUT" {
				t.Err = &net.DNSError{
					Err:       context.DeadlineExceeded.Error(),
					IsTimeout: true,
				}
			}
		case map[interface{}]interface{}:
			if err := t.fillByMap(item.(map[interface{}]interface{})); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown item type: %T", item)
		}
	}
	return nil
}
func (t *testZoneRecord) fillByMap(m map[interface{}]interface{}) error {
	for k, v := range m {
		if k == "MX" {
			items, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("MX value is not a list")
			}
			if len(items) != 2 {
				return fmt.Errorf("MX value is not a list of length 2")
			}
			pref, ok := items[0].(int)
			if !ok {
				return fmt.Errorf("the first item of MX is not an integer")
			}
			host, ok := items[1].(string)
			if !ok {
				return fmt.Errorf("the second item of MX is not a string")
			}
			t.MX = append(t.MX, net.MX{Host: host, Pref: uint16(pref)})
			continue
		}

		str, err := parseRecordValue(v)
		if err != nil {
			return err
		}

		switch k {
		case "SPF", "TXT":
			t.TXT = append(t.TXT, str)
		case "A":
			t.A = append(t.A, str)
		case "AAAA":
			t.AAAA = append(t.AAAA, str)
		case "PTR":
			t.PTR = append(t.PTR, str)
		case "CNAME":
			t.CNAME = str
		default:
			return fmt.Errorf("unknown key %s", k)
		}
	}
	return nil
}
func parseRecordValue(i interface{}) (string, error) {
	switch i.(type) {
	case string:
		return i.(string), nil
	case []interface{}:
		var val string
		for _, v := range i.([]interface{}) {
			if vv, ok := v.(string); ok {
				val += vv
			} else {
				return "", fmt.Errorf("unable to parse DNS record value: %T", v)
			}
		}
		return val, nil
	default:
		return "", fmt.Errorf("unknown type: %T", i)
	}
}
func loadTestSuites(path string) ([]testSuite, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var suites []testSuite
	dec := yaml.NewDecoder(f)
	for {
		var suite testSuite
		if err := dec.Decode(&suite); err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		suites = append(suites, suite)
	}
	return suites, nil
}

func TestVerifier_Test(t *testing.T) {
	return
	suites, err := loadTestSuites("testdata/openspf-rfc7208-tests.yml")
	if err != nil {
		t.Errorf("Failed to load test suites: %s", err)
	}
	for _, suite := range suites {
		t.Run(suite.Description, func(t *testing.T) {
			r := &mockdns.Resolver{Zones: make(map[string]mockdns.Zone)}
			for s, record := range suite.ZoneData {
				r.Zones[dns.Fqdn(s)] = mockdns.Zone(record)
			}
			for tName, tt := range suite.Tests {
				t.Run(tName, func(t *testing.T) {
					v := NewVerifier(tt.MailFrom, net.ParseIP(tt.Host), tt.Helo)
					v.SetResolver(r)
					got, err := v.Test(context.TODO())

					isOneOfExpect := false
					for _, result := range tt.Result {
						if result == got {
							isOneOfExpect = true
							break
						}
					}
					if !isOneOfExpect {
						t.Errorf("wants %v, got %s", tt.Result, got)
						if err != nil {
							t.Log(err)
						}
						t.Logf("spec: %s, %s ", tt.Spec, tt.Description)
						t.Log(tt.Comment)
					}
				})
			}
		})

	}
}

func loadMockResolver(zf string) (*mockdns.Resolver, error) {
	zr, err := os.Open(zf)
	if err != nil {
		return nil, err
	}

	zones := map[string]mockdns.Zone{}
	zp := dns.NewZoneParser(zr, "", "")
	zp.SetDefaultTTL(300)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		hdr := rr.Header()
		zone, ok := zones[hdr.Name]
		if !ok {
			zone = mockdns.Zone{}
		}

		switch hdr.Rrtype {
		case dns.TypeA:
			rrA := rr.(*dns.A)
			zone.A = append(zone.A, rrA.A.String())
		case dns.TypeAAAA:
			rrAAAA := rr.(*dns.AAAA)
			zone.AAAA = append(zone.AAAA, rrAAAA.AAAA.String())
		case dns.TypeMX:
			rrMX := rr.(*dns.MX)
			zone.MX = append(zone.MX, net.MX{Host: rrMX.Mx, Pref: rrMX.Preference})
		case dns.TypeCNAME:
			rrCNAME := rr.(*dns.CNAME)
			zone.CNAME = rrCNAME.Target
		case dns.TypePTR:
			rrPTR := rr.(*dns.PTR)
			zone.PTR = append(zone.PTR, rrPTR.Ptr)
		default:
			return nil, fmt.Errorf("unexpected TYPE: %s", rr.String())
		}

		zones[hdr.Name] = zone
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}
	return &mockdns.Resolver{Zones: zones}, nil
}

func addMockSPFRecord(resolver *mockdns.Resolver, domain, record string) {
	domain = dns.Fqdn(domain)
	zone, ok := resolver.Zones[domain]
	if !ok {
		zone = mockdns.Zone{}
	}
	zone.TXT = append(zone.TXT, record)
	resolver.Zones[domain] = zone
}

func TestVerifier_RFC7208Appendix1(t *testing.T) {

	var cases = []struct {
		spf  string //published records for example.com
		ip   string // <ip> would cause check_host() to return "pass"
		want Result
	}{
		{"v=spf1 +all", "10.0.0.1", ResultPass},

		{"v=spf1 a -all", "192.0.2.10", ResultPass},
		{"v=spf1 a -all", "192.0.2.11", ResultPass},

		{"v=spf1 a:example.org -all", "192.0.2.11", ResultPermError},

		{"v=spf1 mx -all", "192.0.2.129", ResultPass},
		{"v=spf1 mx -all", "192.0.2.130", ResultPass},

		{"v=spf1 mx:example.org -all", "192.0.2.140", ResultPass},

		{"v=spf1 mx mx:example.org -all", "192.0.2.129", ResultPass},
		{"v=spf1 mx mx:example.org -all", "192.0.2.130", ResultPass},
		{"v=spf1 mx mx:example.org -all", "192.0.2.140", ResultPass},

		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.128", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.131", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.141", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.143", ResultPass},

		{"v=spf1 ptr -all", "192.0.2.65", ResultPass},
		{"v=spf1 ptr -all", "192.0.2.140", ResultFail},
		{"v=spf1 ptr -all", "10.0.0.4", ResultFail},

		{"v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.65", ResultFail},
		{"v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.129", ResultPass},
	}
	for _, s := range cases {
		t.Run(s.spf, func(t *testing.T) {
			resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a1.zone")
			if err != nil {
				t.Error(err)
			}
			addMockSPFRecord(resolver, "example.com", s.spf)

			v := NewVerifier("test@example.com", net.ParseIP(s.ip), "example.net")
			v.SetResolver(resolver)

			got, err := v.Test(context.TODO())
			if got != s.want {
				t.Errorf("incorrect result, want=%s, got=%s", s.want, got)
				t.Error(err)
			}
		})
	}
}

func TestVerifier_RFC7208Appendix2(t *testing.T) {
	resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a1.zone")
	if err != nil {
		t.Error(err)
	}
	addMockSPFRecord(resolver, "example.com", "v=spf1 mx -all")
	addMockSPFRecord(resolver, "example.net", "v=spf1 a -all")
	addMockSPFRecord(resolver, "example.org", "v=spf1 include:example.com include:example.net -all")
	addMockSPFRecord(resolver, "la.example.org", "v=spf1 redirect=example.org")

	ip := net.ParseIP("192.0.2.129")
	v := NewVerifier("test@la.example.org", ip, "example.net")
	v.SetResolver(resolver)

	got, err := v.Test(context.TODO())
	want := ResultPass
	if got != want {
		t.Errorf("incorrect result, want=%s, got=%s", want, got)
		t.Error(err)
	}

}
