package dnsprobe

type Status string

const (
	StatusResolved Status = "resolved"
	StatusBlocked  Status = "blocked"
	StatusPrivate  Status = "private"
	StatusCNAME    Status = "cname"
	StatusNXDOMAIN Status = "nxdomain"
	StatusError    Status = "error"
)

type Classification struct {
	Status    Status   `json:"status"`
	BlockedBy string   `json:"blocked_by,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type ChainStep struct {
	Name           string         `json:"name"`
	Classification Classification `json:"classification"`
}

type ResolverResult struct {
	ResolverName string      `json:"resolver_name"`
	ResolverAddr string      `json:"resolver_addr"`
	Steps        []ChainStep `json:"steps"`
	Status       Status      `json:"status"`
	Error        string      `json:"error,omitempty"`
}
