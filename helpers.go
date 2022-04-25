package main

import (
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func setDefaultRule(rule int) {
	ViewRuleDefault = rule
}

func parseRule(s string) int {
	if strings.EqualFold(s, "allow") {
		return RuleAllow
	}
	if strings.EqualFold(s, "deny") {
		return RuleDeny
	}
	return RuleDefault
}

func allowIsDefault() bool {
	switch ViewRuleDefault {
	case RuleAllow:
		return true
	case RuleDeny:
	case RuleDefault:
	default:
	}
	return false
}

func parseNetList(ips []string) ([]net.IPNet, error) {
	var nets = make([]net.IPNet, len(ips))

	for i, ip := range ips {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		_, net, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, err
		}

		nets[i] = *net
	}

	return nets, nil
}

/**
 * Check if `ip` is in any of the network `nets`.
 */
func ip_in_nets(ip *net.IP, nets []net.IPNet) bool {
	for _, net := range nets {
		if net.Contains(*ip) {
			return true
		}
	}
	return false
}

func get_client_ip(w dns.ResponseWriter) net.IP {
	remote := w.RemoteAddr().String()
	remote_ip_str := strings.Split(remote, ":")[0]
	return net.ParseIP(remote_ip_str)
}

func getEnvBool(s string, d bool) bool {
	v := os.Getenv(s)
	if v == "" {
		return d
	}
	if strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		return true
	}
	return false
}

func getEnvString(s string, d string) string {
	v := os.Getenv(s)
	if v == "" {
		return d
	}
	return v
}
