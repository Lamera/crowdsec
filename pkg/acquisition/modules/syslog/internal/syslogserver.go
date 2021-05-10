package syslogserver

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"
)

type SyslogServer struct {
	listenAddr string
	port       int
	channel    chan SyslogMessage
	udpConn    *net.UDPConn
	readTomb   *tomb.Tomb
}

type SyslogMessage struct {
	Message []byte
	Client  string
}

func (s *SyslogServer) Listen(listenAddr string, port int) error {

	s.listenAddr = listenAddr
	s.port = port
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.listenAddr, s.port))
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.udpConn = udpConn
	s.udpConn.SetReadBuffer(1024 * 8) // FIXME probably

	return nil
}

func (s *SyslogServer) SetChannel(c chan SyslogMessage) {
	s.channel = c
}

func (s *SyslogServer) StartServer() {
	go func() {
		for {
			b := make([]byte, 1024)
			n, addr, err := s.udpConn.ReadFrom(b)
			if err != nil {
				//not sure what to do ?
				fmt.Printf("err while reading from client : %s", err)
				continue
			}
			s.channel <- SyslogMessage{Message: b[:n], Client: addr.String()}
		}
	}()
}

func (s *SyslogServer) KillServer() error {
	err := s.udpConn.Close()
	if err != nil {
		return errors.Wrap(err, "could not close UDP connection")
	}
	return nil
}
