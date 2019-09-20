package auth

import (
	"github.com/colligence-io/signServer/util"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"net"
)

type App struct {
	KeyPair     stellarkp.KP
	CIDRChecker cidranger.Ranger
}

// check CIDR range match for ip
func (aa *App) CheckCIDR(ip net.IP) bool {
	contains, e := aa.CIDRChecker.Contains(ip)
	if e != nil {
		return false
	}
	return contains
}

// check CIDR range match for ip string
func (aa *App) CheckStringCIDR(addr string) bool {
	if ip := util.GetIPFromAddress(addr); ip != nil {
		return aa.CheckCIDR(ip)
	}
	return false
}
