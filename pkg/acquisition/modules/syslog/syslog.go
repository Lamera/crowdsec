package syslog

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/influxdata/go-syslog/v3/rfc3164"
	"github.com/influxdata/go-syslog/v3/rfc5424"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type SyslogConfiguration struct {
	Proto string `yaml:"protocol,omitempty"`
	Port  int    `yaml:"port,omitempty"`
	Addr  string `yaml:"addr,omitempty"`
	//TODO: Add TLS support
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SyslogSource struct {
	config SyslogConfiguration
	logger *log.Entry
	server *syslogserver.SyslogServer
}

func (s *SyslogSource) GetName() string {
	return "syslog"
}

func (s *SyslogSource) GetMode() string {
	return s.config.Mode
}

func (s *SyslogSource) Dump() interface{} {
	return s
}

func (s *SyslogSource) CanRun() error {
	return nil
}

func (s *SyslogSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (s *SyslogSource) ConfigureByDSN(dsn string, labelType string, logger *log.Entry) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SyslogSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SyslogSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	s.logger = logger
	s.logger.Infof("Starting syslog datasource configuration")
	syslogConfig := SyslogConfiguration{}
	syslogConfig.Mode = configuration.TAIL_MODE
	err := yaml.UnmarshalStrict(yamlConfig, &syslogConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse syslog configuration")
	}
	if syslogConfig.Addr == "" {
		syslogConfig.Addr = "127.0.0.1" //do we want a usable or secure default ?
	}
	if syslogConfig.Port == 0 {
		syslogConfig.Port = 514
	}
	if syslogConfig.Proto == "" {
		syslogConfig.Proto = "udp"
	}
	s.config = syslogConfig
	return nil
}

func (s *SyslogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	c := make(chan syslogserver.SyslogMessage)
	s.server = &syslogserver.SyslogServer{}
	s.server.SetChannel(c)
	err := s.server.Listen(s.config.Addr, s.config.Port)
	if err != nil {
		return errors.Wrap(err, "could not start syslog server")
	}
	s.server.StartServer()
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/syslog/live")
		return s.handleSyslogMsg(out, t, c)
	})
	return nil
}

func (s *SyslogSource) handleSyslogMsg(out chan types.Event, t *tomb.Tomb, c chan syslogserver.SyslogMessage) error {
	for {
		select {
		case <-t.Dying():
			s.server.KillServer()
			s.logger.Info("Syslog datasource is dying")
		case syslogLine := <-c:
			var line string
			var ts time.Time
			//spew.Dump(syslogLine)
			p := rfc5424.NewParser()
			m, err := p.Parse(syslogLine.Message)
			if err != nil {
				/*	p2 := rfc3164.NewParser(rfc3164.WithYear(rfc3164.CurrentYear{}))
					m, err = p2.Parse(syslogLine)
					if err != nil {
						fmt.Printf("err while parsing: %s", err)
						continue
					}
					continue*/
				s.logger.Infof("could not parse message as RFC5424, fallinb back to RFC3164 : %s", err)
				p = rfc3164.NewParser(rfc3164.WithYear(rfc3164.CurrentYear{}))
				m, err = p.Parse(syslogLine.Message)
				if err != nil {
					fmt.Printf("could not parse message as RFC3164 : %s", err)
					continue
				}
				//TODO: check if the fields are not nil
				msg := m.(*rfc3164.SyslogMessage)
				ts = *msg.Timestamp
				line = fmt.Sprintf("%s %s %s: %s", *msg.Timestamp, *msg.Hostname,
					*msg.Appname, *msg.Message)
			} else {
				msg := m.(*rfc5424.SyslogMessage)
				ts = *msg.Timestamp
				//TODO: check if the fields are not nil
				line = fmt.Sprintf("%s %s %s[%s]: %s", *msg.Timestamp, *msg.Hostname,
					*msg.Appname, *msg.ProcID, *msg.Message)
			}
			//spew.Dump(m)
			//rebuild the syslog line from the part
			l := types.Line{}
			l.Raw = line
			//l.Module = s.GetName() // Uncomment after rebase
			l.Labels = s.config.Labels
			l.Time = ts
			l.Src = syslogLine.Client
			l.Process = true
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		}
	}
}
