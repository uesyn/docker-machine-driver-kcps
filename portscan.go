package dockermachinedriverkcps

import (
	"net"
	"strconv"
	"time"
)

type PortScanner struct {
	Host    string
	Port    int
	Timeout time.Duration
}

func NewPortScanner(host string, port int, timeout time.Duration) *PortScanner {
	return &PortScanner{
		Host:    host,
		Port:    port,
		Timeout: timeout,
	}
}

func (p *PortScanner) IsOpen() bool {
	h := p.Host + ":" + strconv.Itoa(p.Port)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", h)
	if err != nil {
		return false
	}

	conn, err := net.DialTimeout("tcp", tcpAddr.String(), p.Timeout)
	if err != nil {
		return false
	}

	defer conn.Close()
	return true
}
