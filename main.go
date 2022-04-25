package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var (
	Debug             = false
	ViewDefaultAction = Exclude
)

func get_action(s string) int {
	if strings.EqualFold(s, "include") {
		return Include
	}
	if strings.EqualFold(s, "exclude") {
		return Exclude
	}
	return Default
}

type View struct {
	name    string
	sources []net.IPNet
	include []net.IPNet
	exclude []net.IPNet
	action  int
}

func (v View) Contains(ip *net.IP) bool {
	return ip_in_nets(ip, v.sources)
}

func getDefaultResult() bool {
	switch ViewDefaultAction {
	case Include:
		return true
	case Exclude:
	case Default:
	default:
	}
	return false
}

func (v View) Apply(ip *net.IP) bool {
	if ip_in_nets(ip, v.include) {
		return true
	}
	if ip_in_nets(ip, v.exclude) {
		return false
	}
	if v.action == Exclude {
		return false
	}
	if v.action == Include {
		return true
	}
	return getDefaultResult()
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
 *
 * Config file.
 *
 */
type ConfigView struct {
	Name    string   `yaml:"name"`
	Sources []string `yaml:"sources"`
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
	Action  string   `yaml:"action"`
}

func (c ConfigView) CopyToView(v *View) error {
	v.name = c.Name
	v.action = get_action(c.Action)

	sources, err := parseNetList(c.Sources)
	if err != nil {
		return err
	}
	include, err := parseNetList(c.Include)
	if err != nil {
		return err
	}
	exclude, err := parseNetList(c.Exclude)
	if err != nil {
		return err
	}

	v.sources = sources
	v.include = include
	v.exclude = exclude

	return nil
}

type Config struct {
	Debug         bool   `yaml:"debug"`
	DefaultAction string `yaml:"action"`
	Upstream      string `yaml:"upstream"`
	Listen        string `yaml:"listen"`
	Logging       struct {
		IncludeDate bool `yaml:"include_date"`
	} `yaml:"logging"`
	Views []ConfigView `yaml:"views"`
}

func (c Config) GetViews() ([]View, error) {
	if len(c.Views) == 0 {
		return nil, errors.New("missing 'views' configuration")
	}
	var views = make([]View, len(c.Views))

	for i, cv := range c.Views {
		err := cv.CopyToView(&views[i])
		if err != nil {
			return nil, err
		}
	}

	return views, nil
}

/**
 *
 * Helper functions
 *
 */

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

func remove_answer(r *dns.Msg, i int) {
	if Debug {
		log.Printf("Removing %d '%s', %d remain", i, r.Answer[i], len(r.Answer)-1)
	}
	r.Answer = append(r.Answer[:i], r.Answer[i+1:]...)
}

func rewrite_for_view(view View, r *dns.Msg) {
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

		if view.Apply(&addr) {
			if Debug {
				log.Printf("View '%s' includes %d %s", view.name, rtype, addr)
			}
			continue
		}
		if Debug {
			log.Printf("View '%s' excludes %d %s", view.name, rtype, addr)
		}
		remove_answer(r, i-removed)
		removed += 1
	}
}

func get_client_ip(w dns.ResponseWriter) net.IP {
	remote := w.RemoteAddr().String()
	remote_ip_str := strings.Split(remote, ":")[0]
	return net.ParseIP(remote_ip_str)
}

type ViewFilter struct {
	Views  []View
	Config Config
}

func (f ViewFilter) apply_views(w dns.ResponseWriter, req *dns.Msg) {
	// func apply_views(w dns.ResponseWriter, req *dns.Msg) {

	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}

	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, f.Config.Upstream)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	if Debug {
		log.Printf("trying %d views", len(f.Views))
	}

	remote := get_client_ip(w)
	for _, v := range f.Views {
		if v.Contains(&remote) {
			if Debug {
				log.Printf("applying view '%s' for remote %s", v.name, remote)
			}
			rewrite_for_view(v, resp)
		}
	}

	w.WriteMsg(resp)
}

func load_config(config *Config, paths ...string) bool {
	for _, path := range paths {

		if path == "" {
			continue
		}

		if _, err := os.Stat(path); err != nil {
			if Debug {
				log.Printf("not loading from '%s', reason: %s", path, err)
			}
			continue
		}

		data, e := os.ReadFile(path)
		if e != nil {
			if Debug {
				log.Printf("not loading from %s, reason: %s", path, e)
			}
			continue
		}

		var tmp Config
		err := yaml.Unmarshal(data, &tmp)
		if err == nil {
			if Debug {
				log.Printf("config loaded from %s", path)
			}
			*config = Config(tmp)
			return true
		}
	}
	return false
}

func main() {
	var config Config

	config_filename := "viewdns"

	loaded := load_config(&config,
		os.Getenv("DVIEW_CONFIG"),
		"/etc/"+config_filename+"/"+config_filename+".yaml",
		"/etc/"+config_filename+"/"+config_filename+".yml",
		config_filename+".yaml",
		config_filename+".yml")

	if !loaded {
		fmt.Println("cannot load config file, exiting ...")
		os.Exit(1)
	}

	Debug = config.Debug

	if !config.Logging.IncludeDate {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	Views, err := config.GetViews()
	if err != nil {
		log.Printf("error processing views: %s\n", err)
		os.Exit(1)
	}

	if Debug {
		for i, v := range Views {
			log.Printf("[view %d] %+v\n", i, v)
		}
	}

	udpServer := &dns.Server{Addr: config.Listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: config.Listen, Net: "tcp"}
	fitler := ViewFilter{Views: Views, Config: config}
	dns.HandleFunc(".", fitler.apply_views)

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

	log.Print("starting ...")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Print("shutting down ...")

	udpServer.Shutdown()
	tcpServer.Shutdown()
}
