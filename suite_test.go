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
