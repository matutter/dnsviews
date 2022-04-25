package main

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const (
	RuleAllow   int = 0
	RuleDeny    int = 1
	RuleDefault int = 2
)

type View struct {
	name    string
	sources []net.IPNet
	include []net.IPNet
	exclude []net.IPNet
	rule    int
}

func (v View) Contains(ip *net.IP) bool {
	return ip_in_nets(ip, v.sources)
}

func (v View) Apply(ip *net.IP) bool {
	if ip_in_nets(ip, v.include) {
		return true
	}
	if ip_in_nets(ip, v.exclude) {
		return false
	}
	if v.rule == RuleDeny {
		return false
	}
	if v.rule == RuleAllow {
		return true
	}
	return allowIsDefault()
}

func remove_answer(r *dns.Msg, i int) {
	if Debug {
		log.Printf("removing %d '%s', %d remain", i, r.Answer[i], len(r.Answer)-1)
	}
	r.Answer = append(r.Answer[:i], r.Answer[i+1:]...)
}

func (v View) Rewrite(r *dns.Msg) {
	var rr dns.RR
	var i int
	removed := 0
	for i, rr = range r.Answer {
		rtype := rr.Header().Rrtype
		if rtype != dns.TypeA && rtype != dns.TypeAAAA {
			continue
		}

		parts := strings.Split(rr.String(), "\t")
		if len(parts) == 0 {
			continue
		}

		addr := net.ParseIP(parts[len(parts)-1])
		if addr == nil {
			continue
		}

		if v.Apply(&addr) {
			if Debug {
				log.Printf("view '%s' includes %d %s", v.name, rtype, addr)
			}
			continue
		}
		if Debug {
			log.Printf("view '%s' excludes %d %s", v.name, rtype, addr)
		}
		remove_answer(r, i-removed)
		removed += 1
	}
}
