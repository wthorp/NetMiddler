package main

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var savedRules []*nftables.Rule

func enableProxy(port int) error {
	conn := &nftables.Conn{}

	// Get the current table and chain for the NAT table
	natTable := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}

	// List rules in the 'OUTPUT' chain
	chain := &nftables.Chain{
		Table: natTable,
		Name:  "OUTPUT",
	}
	var err error
	savedRules, err = c.GetRules(chain)
	if err != nil {
		return err
	}

	return SetProxyRules(conn, uint16(port))
}

// disableProxy restores the saved iptables state
func disableProxy() error {
	c := &nftables.Conn{}

	// First, flush the chain to remove existing rules
	c.FlushChain(&nftables.Chain{
		Table: &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "nat",
		},
		Name: "OUTPUT",
	})

	// Re-add the saved rules
	for _, rule := range savedRules {
		c.AddRule(rule)
	}

	// Commit the restored rules
	return c.Flush()
}

// SetProxyRules sets iptables rules for HTTP/S proxy redirection
func SetProxyRules(c *nftables.Conn, proxyPort uint16) error {
	natTable := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Table:    natTable,
		Name:     "OUTPUT",
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &accept,
	}

	// HTTP (port 80) redirection
	rule := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // This is where the destination port is in the TCP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0, 80}, // Port 80
			},
			&expr.Immediate{
				Register: 1,
				Data:     []byte{0, byte(proxyPort)}, // Redirect to proxy port
			},
		},
	}

	// Add the rule to iptables
	c.AddRule(rule)

	// HTTPS (port 443) redirection
	ruleHTTPS := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // Destination port offset in TCP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{1, 187}, // Port 443
			},
			&expr.Immediate{
				Register: 1,
				Data:     []byte{0, byte(proxyPort)}, // Redirect to proxy port
			},
		},
	}

	// Add the rule to iptables
	c.AddRule(ruleHTTPS)

	// Commit the changes
	return c.Flush()
}
