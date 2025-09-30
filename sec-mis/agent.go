package secmis

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/n1k1x86/rasp-agents/base"
	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
)

type SecMisAgent struct {
	*base.BaseClient
	checkingPortsTimeout time.Duration
	rules                *Rules
}

func (s *SecMisAgent) CheckOpenedPorts() {
	for _, port := range s.rules.Ports {
		go s.checkPort(port)
	}
}

func (s *SecMisAgent) RunPortChecker() {
	ticker := time.NewTicker(s.checkingPortsTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-s.GetCtx().Done():
			return
		case <-ticker.C:
			s.CheckOpenedPorts()
		}
	}
}

func (s *SecMisAgent) checkPort(port string) {
	defer func() {
		r := recover()
		if r != nil {
			log.Printf("panic was recovered in checkPort method: %s", r)
		}
	}()

	conn, err := net.Dial("tcp", "127.0.0.1:"+port)

	if err != nil {
		switch err := err.(type) {
		case *net.OpError:
			if err.Addr == nil {
				log.Printf("Port %s: Invalid address\n", port)
			} else {
				log.Printf("Port %s: Closed\n", port)
			}
		default:
			log.Printf("Port %s: Unknown error: %s\n", port, err.Error())
		}
		return
	}

	defer conn.Close()
	log.Printf("WARNING: Port %s is opened\n", port)
}

func (s *SecMisAgent) ReadJsonConfigs() error {
	fileNames, err := filepath.Glob("*.json")
	if err != nil {
		return nil
	}
	for _, file := range fileNames {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("error while reading a file %s, error: %s", file, err.Error())
			continue
		}
		go s.scanJson(data)
	}
	return nil
}

func (s *SecMisAgent) scanJson(bytes []byte) {
	defer func() {
		r := recover()
		if r != nil {
			log.Printf("panic was recovered in scanJson, error: %s", r)
		}
	}()

	var data interface{}
	err := json.Unmarshal(bytes, &data)
	if err != nil {
		log.Printf("error while unmarshalling a json, error: %s", err.Error())
		return
	}

	travelJson(data)
}

func travelJson(data interface{}) {
	switch v := data.(type) {
	default:
		return
	}
}

func (s *SecMisAgent) ReadYamlConfigs() error {
	fileNames, err := filepath.Glob("*.yaml")
	if err != nil {
		return nil
	}
	for _, file := range fileNames {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("error while reading a file %s, error: %s", file, err.Error())
			continue
		}
		go s.scanYaml(data)
	}
	return nil
}

func (s *SecMisAgent) scanYaml(bytes []byte) {
	defer func() {
		r := recover()
		if r != nil {
			log.Printf("panic was recovered in scanJson, error: %s", r)
		}
	}()

	var data interface{}
	err := json.Unmarshal(bytes, &data)
	if err != nil {
		log.Printf("error while unmarshalling a json, error: %s", err.Error())
		return
	}

	travelYaml(data)
}

func travelYaml(data interface{}) {}

func (s *SecMisAgent) AcceptRules(rules *rasp_rpc.NewRules) {
	s.rules.ConfigParams = rules.GetSecMisRules().ConfigParams
	s.rules.Ports = rules.GetSecMisRules().Ports
	log.Println("new rules were accepted for mis config agent")
}

func NewClient(ctx context.Context, addr, port string, healthAddr string, checkingHealthTimeout, checkingPortsTimeout time.Duration) (*SecMisAgent, error) {
	SecMisAgent := &SecMisAgent{
		rules:                &Rules{},
		checkingPortsTimeout: checkingPortsTimeout,
	}

	baseClient, err := base.NewBaseClient(ctx, addr, port, base.SEC_MIS_AGENT, SecMisAgent.AcceptRules, checkingHealthTimeout, healthAddr)
	if err != nil {
		return nil, err
	}
	SecMisAgent.BaseClient = baseClient

	return SecMisAgent, nil
}
