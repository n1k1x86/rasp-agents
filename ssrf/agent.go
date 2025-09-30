package ssrf

import (
	"context"
	"log"
	"regexp"
	"slices"
	"time"

	base "github.com/n1k1x86/rasp-agents/base"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
)

type SSRFClient struct {
	*base.BaseClient
	rules Rules
}

func (s *SSRFClient) CheckBlackListHost(host string) bool {
	return slices.Contains(s.rules.HostsRules, host)
}

func (s *SSRFClient) CheckBlackListIP(ip string) bool {
	return slices.Contains(s.rules.IPRules, ip)
}

func (s *SSRFClient) CheckBlackListRegexp(target string) (bool, error) {
	res := false
	for _, pattern := range s.rules.RegexpRules {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Println("error in rule: ", pattern)
			continue
		}
		res = re.MatchString(target)
		if res {
			break
		}
	}
	return res, nil
}

func (s *SSRFClient) CheckBlackListScheme(target string) bool {
	return slices.Contains(s.rules.SchemeRules, target)
}

func (s *SSRFClient) UpdateRules(ipRules, hostsRules, regexpRules []string) {
	newRules := NewRules(ipRules, hostsRules, regexpRules)
	s.rules = newRules
	log.Println("rules were updated")
}

func NewRules(ipRules, hostsRules, regexpRules []string) Rules {
	return Rules{
		IPRules:     ipRules,
		HostsRules:  hostsRules,
		RegexpRules: regexpRules,
	}
}

func (s *SSRFClient) AcceptRules(rules *rasp_rpc.NewRules) {
	s.rules.HostsRules = rules.GetSSRFRules().HostRules
	s.rules.IPRules = rules.GetSSRFRules().IPRules
	s.rules.RegexpRules = rules.GetSSRFRules().RegexpRules
	log.Println("got new rules, rules", rules)
}

func NewSSRFClient(ctx context.Context, addr, port, healthAddr string, healthCheckTimeout time.Duration) (*SSRFClient, error) {

	ssrfClient := &SSRFClient{
		rules: Rules{},
	}

	baseClient, err := base.NewBaseClient(ctx, addr, port, base.SSRF_AGENT, ssrfClient.AcceptRules, healthCheckTimeout, healthAddr)
	if err != nil {
		return nil, err
	}

	ssrfClient.BaseClient = baseClient
	return ssrfClient, nil
}
