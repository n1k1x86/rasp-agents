package base

import (
	"context"
	"fmt"
	"io"
	"log"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type BaseClient struct {
	Stub      rasp_rpc.RASPCentralClient
	AgentID   string
	ServiceID string
	AgentType string
	ctx       context.Context
}

func (b *BaseClient) RegAgent(agentName, serviceID string) error {
	req := newRegAgentRequest(agentName, serviceID, b.AgentType)
	resp, err := b.Stub.RegAgent(b.ctx, req)
	if err != nil {
		return err
	}
	b.AgentID = resp.AgentID
	b.ServiceID = req.ServiceID
	b.AgentType = req.AgentType
	b.RunUpdater()

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

func (b *BaseClient) AcceptRules(rules *rasp_rpc.NewRules) error {
	return fmt.Errorf("unimplimented Accept Rules method")
}

func (b *BaseClient) RunUpdater() error {
	req := &rasp_rpc.AgentRequest{
		AgentID:   b.AgentID,
		AgentType: b.AgentType,
	}
	stream, err := b.Stub.SyncRules(b.ctx, req)
	if err != nil {
		log.Println(err)
		return err
	}
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				log.Printf("Panic in updater: %b", r)
			}
		}()
		for {
			select {
			case <-b.ctx.Done():
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
					err = b.AcceptRules(newRules)
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
	}()
	log.Println("updater for ssrf agent is running")
	return nil
}

func (b *BaseClient) DeleteAgent() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := &rasp_rpc.AgentRequest{
		AgentID:   b.AgentID,
		AgentType: b.AgentType,
	}
	resp, err := b.Stub.CloseAgent(ctx, req)
	if err != nil {
		return err
	}
	log.Println(resp.Detail)
	return nil
}

func NewBaseClient(ctx context.Context, addr, port, agentType string) (*BaseClient, error) {
	client, err := grpc.NewClient(fmt.Sprintf("%s:%s", addr, port), grpc.WithTransportCredentials(insecure.NewCredentials()))
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

	base := &BaseClient{
		Stub:      stub,
		AgentType: agentType,
		ctx:       ctx,
	}

	go func() {
		<-ctx.Done()
		err = CloseClient(client)
		if err != nil {
			log.Panic(err)
		}
	}()

	return base, nil
}
