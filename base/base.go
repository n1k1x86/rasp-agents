package base

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type BaseClient struct {
	Stub                  rasp_rpc.RASPCentralClient
	AgentID               string
	ServiceID             string
	AgentType             string
	HealthAddr            string
	CheckingHealthTimeout time.Duration
	RulesAcceptor         func(rules *rasp_rpc.NewRules)
	ctx                   context.Context
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

func AcceptRules(rules *rasp_rpc.NewRules) {
	log.Println("unimplimented Accept Rules method")
}

func (b *BaseClient) HealthChecker() {
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
			req, err := http.NewRequest("GET", "http://"+b.HealthAddr+"/general/health", nil)
			if err != nil {
				log.Printf("error while creating request to rasp health: %s", err.Error())
				time.Sleep(b.CheckingHealthTimeout)
				continue
			}
			client := http.Client{}
			httpResp, err := client.Do(req)
			defer httpResp.Body.Close()
			if err != nil {
				log.Printf("error getting rasp health: %s", err.Error())
				time.Sleep(b.CheckingHealthTimeout)
				continue
			}
			if httpResp.StatusCode == http.StatusOK {
				log.Println("health is ok, rasp is available")
				return
			}
			time.Sleep(b.CheckingHealthTimeout)
			continue
		}
	}
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
						log.Println("END OF STREAM in updater, rasp-central unhealth, run health-cheker")
						b.HealthChecker()
						stream, err = b.Stub.SyncRules(b.ctx, req)
						if err != nil {
							log.Println(err)
						}
						continue
					}
					log.Println(err)
				}
				if newRules != nil {
					b.RulesAcceptor(newRules)
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

func NewBaseClient(ctx context.Context, addr, port, agentType string, rulesAcceptor func(rules *rasp_rpc.NewRules), checkingHealthTimeout time.Duration, healthAddr string) (*BaseClient, error) {
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

	if rulesAcceptor == nil {
		rulesAcceptor = AcceptRules
	}

	base := &BaseClient{
		Stub:                  stub,
		AgentType:             agentType,
		ctx:                   ctx,
		RulesAcceptor:         rulesAcceptor,
		HealthAddr:            healthAddr,
		CheckingHealthTimeout: checkingHealthTimeout,
	}

	go func() {
		<-ctx.Done()

		err := base.DeleteAgent()
		if err != nil {
			log.Panic(err)
		}

		err = CloseClient(client)
		if err != nil {
			log.Panic(err)
		}
	}()

	return base, nil
}
