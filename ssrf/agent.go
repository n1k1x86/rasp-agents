package ssrf

import (
	"context"
	"log"
	"regexp"
	"slices"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SSRFClient struct {
	Stub    rasp_rpc.RASPCentralClient
	rules   Rules
	agentID string
	ctx     context.Context
}

func (s *SSRFClient) RegAgent(hostRules, ipRules, regexpRules []string,
	serviceName, serviceDescription, agentName, updateURL string) error {
	req := NewRegAgentRequest(hostRules, ipRules, regexpRules,
		serviceName, serviceDescription, agentName, updateURL)
	resp, err := s.Stub.RegSSRFAgent(s.ctx, req)
	if err != nil {
		return err
	}
	s.agentID = resp.AgentID

	log.Println(resp.Detail)
	return nil
}

func (s *SSRFClient) DeactivateAgent(serviceName, agentName string) error {
	req := NewDeactivateAgentRequest(serviceName, agentName, s.agentID)
	resp, err := s.Stub.DeactivateSSRFAgent(s.ctx, req)
	if err != nil {
		return err
	}

	log.Println(resp.Detail)
	return nil
}

func (s *SSRFClient) CheckHost(host string) bool {
	return slices.Contains(s.rules.HostsRules, host)
}

func (s *SSRFClient) CheckIP(ip string) bool {
	return slices.Contains(s.rules.IPRules, ip)
}

func (s *SSRFClient) CheckRegexp(target string) (bool, error) {
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

func (s *SSRFClient) UpdateRules(ipRules, hostsRules, regexpRules []string) {
	newRules := NewRules(ipRules, hostsRules, regexpRules)
	s.rules = newRules
	log.Println("rules were updated")
}

func CloseClient(client *grpc.ClientConn) error {
	err := client.Close()
	if err != nil {
		return err
	}
	return nil
}

func NewRules(ipRules, hostsRules, regexpRules []string) Rules {
	return Rules{
		IPRules:     ipRules,
		HostsRules:  hostsRules,
		RegexpRules: regexpRules,
	}
}

func NewClient(ctx context.Context) (*SSRFClient, error) {
	client, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	defer func() {
		r := recover()
		if r != nil {
			log.Printf("panic recovered: %s", r)
		}
	}()

	go func() {
		<-ctx.Done()
		err := CloseClient(client)
		if err != nil {
			log.Panic(err)
		}
	}()

	stub := rasp_rpc.NewRASPCentralClient(client)

	ssrfClient := &SSRFClient{
		Stub:  stub,
		ctx:   ctx,
		rules: Rules{},
	}

	return ssrfClient, nil
}
