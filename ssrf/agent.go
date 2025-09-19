package ssrf

import (
	"context"
	"io"
	"log"
	"regexp"
	"slices"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SSRFClient struct {
	Stub      rasp_rpc.RASPCentralClient
	rules     Rules
	agentID   string
	serviceID string
	ctx       context.Context
}

func (s *SSRFClient) RegAgent(agentName, serviceID string) error {
	req := NewRegAgentRequest(agentName, serviceID)
	resp, err := s.Stub.RegSSRFAgent(s.ctx, req)
	if err != nil {
		return err
	}
	s.agentID = resp.AgentID
	s.serviceID = req.ServiceID
	s.runUpdater()

	log.Println(resp.Detail)
	return nil
}

func (s *SSRFClient) GetAgentID() string {
	return s.agentID
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

func (s *SSRFClient) AcceptRules(rules *rasp_rpc.NewRules) {
	s.rules.HostsRules = rules.GetRules().HostRules
	s.rules.IPRules = rules.GetRules().IPRules
	s.rules.RegexpRules = rules.GetRules().RegexpRules
	log.Println("got new rules, rules", rules)
}

func (s *SSRFClient) runUpdater() error {
	req := &rasp_rpc.AgentRequest{
		AgentID: s.agentID,
	}
	stream, err := s.Stub.SyncRules(s.ctx, req)
	if err != nil {
		log.Println(err)
		return err
	}
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				log.Printf("Panic in updater: %s", r)
			}
		}()
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				newRules, err := stream.Recv()
				if err != nil {
					if err == io.EOF {
						log.Println("END OF STREAM")
						return
					}
					log.Println(err)
				}
				if newRules != nil {
					s.AcceptRules(newRules)
				}
			}
		}
	}()
	log.Println("updater for ssrf agent is running")
	return nil
}

func (s *SSRFClient) deleteAgent() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := &rasp_rpc.AgentRequest{
		AgentID: s.agentID,
	}
	resp, err := s.Stub.CloseSSRFAgent(ctx, req)
	if err != nil {
		return err
	}
	log.Println(resp.Detail)
	return nil
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

	stub := rasp_rpc.NewRASPCentralClient(client)

	ssrfClient := &SSRFClient{
		Stub:  stub,
		ctx:   ctx,
		rules: Rules{},
	}

	go func() {
		<-ctx.Done()
		err := ssrfClient.deleteAgent()
		if err != nil {
			log.Panic(err)
		}
		err = CloseClient(client)
		if err != nil {
			log.Panic(err)
		}
	}()

	return ssrfClient, nil
}
