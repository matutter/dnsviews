package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

type ViewFilter struct {
	views  []View
	config *Config
}

func (f ViewFilter) filter(w dns.ResponseWriter, req *dns.Msg) {
	// func apply_views(w dns.ResponseWriter, req *dns.Msg) {

	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}

	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, f.config.Upstream)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	if f.config.Debug {
		log.Printf("trying %d views", len(f.views))
	}

	remote := get_client_ip(w)
	for _, v := range f.views {
		if v.Contains(&remote) {
			if f.config.Debug {
				log.Printf("applying view '%s' for remote %s", v.name, remote)
			}
			v.Rewrite(resp)
		}
	}

	w.WriteMsg(resp)
}

func main() {

	config, err := newConfigFromFile(
		ConfigPath, "/etc/dnsviews/views.yml", "views.yml")

	if err != nil {
		fmt.Printf("failed loading config, reason: %s\n", err)
		os.Exit(1)
	}

	if !config.Logging.IncludeDate {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	views, err := config.GetViews()
	if err != nil {
		log.Printf("failed processing views, reason: %s\n", err)
		os.Exit(1)
	}

	if config.Debug {
		for i, v := range views {
			log.Printf("[view %d] %+v\n", i, v)
		}
	}

	udpServer := &dns.Server{Addr: config.Listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: config.Listen, Net: "tcp"}
	fitler := ViewFilter{views: views, config: config}
	dns.HandleFunc(".", fitler.filter)

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	log.Printf("listening on %s", config.Listen)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Print("shutting down")

	udpServer.Shutdown()
	tcpServer.Shutdown()
}
