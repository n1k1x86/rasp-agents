package ssrf

import (
	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
)

func NewRegAgentRequest(hostRules, ipRules, regexpRules []string,
	serviceName, serviceDescription, agentName, updateURL string) *rasp_rpc.RegSSRFAgentRequest {
	return &rasp_rpc.RegSSRFAgentRequest{
		ServiceName:        serviceName,
		ServiceDescription: serviceDescription,
		AgentName:          agentName,
		UpdateURL:          updateURL,
		HostRules:          hostRules,
		IPRules:            ipRules,
		RegexpRules:        regexpRules,
	}
}

type Rules struct {
	IPRules     []string
	HostsRules  []string
	RegexpRules []string
}

func NewDeactivateAgentRequest(serviceName, agentName, agentID string) *rasp_rpc.DeactivateSSRFAgentRequest {
	return &rasp_rpc.DeactivateSSRFAgentRequest{
		ServiceName: serviceName,
		AgentName:   agentName,
		AgentID:     agentID,
	}
}
