package ssrf

import (
	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
)

func NewRegAgentRequest(agentName, serviceID string) *rasp_rpc.RegSSRFAgentRequest {
	return &rasp_rpc.RegSSRFAgentRequest{
		ServiceID: serviceID,
		AgentName: agentName,
	}
}

type Rules struct {
	IPRules     []string
	HostsRules  []string
	RegexpRules []string
}
