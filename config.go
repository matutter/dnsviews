package main

import (
	"errors"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

var (
	ViewRuleDefault = parseRule(getEnvString("DNSVIEWS_DEFAULT_RULE", "deny"))
	Debug           = getEnvBool("DNSVIEWS_DEBUG", false)
	ConfigPath      = os.Getenv("DNSVIEWS_CONFIG")
)

type ConfigView struct {
	Name    string   `yaml:"name"`
	Sources []string `yaml:"sources"`
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
	Rule    string   `yaml:"rule"`
}

func (c ConfigView) CopyToView(v *View) error {
	v.name = c.Name
	v.rule = parseRule(c.Rule)

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
	DataSource  string
	Debug       bool   `yaml:"debug"`
	DefaultRule string `yaml:"default_rule"`
	Upstream    string `yaml:"upstream"`
	Listen      string `yaml:"listen"`
	Logging     struct {
		IncludeDate bool `yaml:"include_date"`
	} `yaml:"logging"`
	Views []ConfigView `yaml:"views"`
}

func (c Config) GetViews() ([]View, error) {
	if len(c.Views) == 0 {
		return nil, errors.New("missing 'views' list")
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

func newConfigFromFile(paths ...string) (*Config, error) {
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

		conf := Config{DataSource: path}
		err := yaml.Unmarshal(data, &conf)
		if err != nil {
			return nil, err
		}

		Debug = conf.Debug
		if Debug {
			log.Printf("loaded %s: %+v\n", path, conf)
		}
		setDefaultRule(parseRule(conf.DefaultRule))
		return &conf, nil
	}

	return nil, errors.New("cannot find views.yml")
}
