package base

import (
	rasp_rpc "github.com/n1k1x86/rasp-grpc-contract/gen/proto"
)

const SSRF_AGENT = "ssrf_agent"
const XSS_AGENT = "xss_agent"

func newRegAgentRequest(agentName, serviceID, agentType string) *rasp_rpc.RegAgentRequest {
	return &rasp_rpc.RegAgentRequest{
		ServiceID: serviceID,
		AgentName: agentName,
		AgentType: agentType,
	}
}
