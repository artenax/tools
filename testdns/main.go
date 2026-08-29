package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var query string

type reply struct {
	resp *dns.Msg
	t    time.Duration
	err  error
}

func (r reply) toString() string {
	if r.err != nil {
		return r.err.Error()
	} else if r.resp != nil {
		return fmt.Sprintf("%s\t[%s]\t[%s]", dns.RcodeToString[r.resp.Rcode], r.t.Round(time.Millisecond).String(), parseIPv4(r.resp))
	} else {
		return "nil response"
	}
}

func parseIPv4(msg *dns.Msg) string {
	if msg == nil {
		return "no IPs"
	}
	var ips []string
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	if len(ips) == 0 {
		return "no IPs"
	}
	return strings.Join(ips, ", ")
}

func exchange(net, servername, addr string) reply {
	c := new(dns.Client)
	c.Net = net
	c.TLSConfig = &tls.Config{ServerName: servername}

	m := new(dns.Msg)
	m.SetQuestion(query+".", dns.TypeA)

	start := time.Now()
	resp, _, err := c.Exchange(m, addr)
	elapsed := time.Since(start)

	return reply{resp, elapsed, err}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:", os.Args[0], "<domain>")
		os.Exit(1)
	}
	query = os.Args[1]

	fmt.Println("Testing", query)

	fmt.Println("...with 1.1.1.1...")
	fmt.Println("[UDP]", exchange("", "1.1.1.1", "1.1.1.1:53").toString())
	fmt.Println("[DoTCP]", exchange("tcp", "1.1.1.1", "1.1.1.1:53").toString())
	fmt.Println("[DoT]", exchange("tcp-tls", "1.1.1.1", "1.1.1.1:853").toString())

	fmt.Println("...with 8.8.8.8...")
	fmt.Println("[UDP]", exchange("", "8.8.8.8", "8.8.8.8:53").toString())
	fmt.Println("[DoTCP]", exchange("tcp", "8.8.8.8", "8.8.8.8:53").toString())
	fmt.Println("[DoT]", exchange("tcp-tls", "8.8.8.8", "8.8.8.8:853").toString())

	fmt.Println("...with 9.9.9.9...")
	fmt.Println("[UDP]", exchange("", "9.9.9.9", "9.9.9.9:53").toString())
	fmt.Println("[DoTCP]", exchange("tcp", "9.9.9.9", "9.9.9.9:53").toString())
	fmt.Println("[DoT]", exchange("tcp-tls", "9.9.9.9", "9.9.9.9:853").toString())
}
