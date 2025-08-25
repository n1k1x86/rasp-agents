package ssrf

import (
	"context"
	"log"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SSRFClient struct {
	Stub    rasp_rpc.RASPCentralClient
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

func (s *SSRFClient) DeactivateAgent(serviceName, agentName, agentID string) error {
	req := NewDeactivateAgentRequest(serviceName, agentName, agentID)
	resp, err := s.Stub.DeactivateSSRFAgent(s.ctx, req)
	if err != nil {
		return err
	}

	log.Println(resp.Detail)
	return nil
}

func CloseClient(client *grpc.ClientConn) error {
	err := client.Close()
	if err != nil {
		return err
	}
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

	go func() {
		<-ctx.Done()
		err := CloseClient(client)
		if err != nil {
			log.Panic(err)
		}
	}()

	stub := rasp_rpc.NewRASPCentralClient(client)

	ssrfClient := &SSRFClient{
		Stub: stub,
		ctx:  ctx,
	}

	return ssrfClient, nil
}
