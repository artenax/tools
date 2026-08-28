// dns-tcp-proxy: слушает DNS-запросы по UDP на локальном порту и
// пересылает их upstream-серверу по TCP (DNS-over-TCP, RFC 7766).
//
// Зачем: некоторые провайдеры подменяют/блокируют обычный
// нешифрованный UDP:53, но не трогают TCP:53. glibc-резолвер сам
// никогда не переключится на TCP, кроме случая truncated-ответа,
// поэтому нужен локальный "переводчик" протокола.
//
// Использование:
//   go build -o dns-tcp-proxy main.go
//   sudo setcap 'cap_net_bind_service=+ep' ./dns-tcp-proxy
//   ./dns-tcp-proxy -listen 127.0.0.1:53 -upstream 1.1.1.1:53
//
// Затем указать 127.0.0.1 как DNS-сервер системы (см. README.md).
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"sync"
	"time"
)

// pending — запрос, ожидающий ответа от upstream-сервера.
// Хранится по "нашему" переписанному ID, чтобы сматчить ответ
// с исходным UDP-клиентом и вернуть ему оригинальный ID запроса.
type pending struct {
	clientAddr *net.UDPAddr
	origID     uint16
	timer      *time.Timer
}

type proxy struct {
	upstream string
	udpConn  *net.UDPConn

	dialMu  sync.Mutex // защищает tcpConn и сериализует запись в него
	tcpConn net.Conn

	mu      sync.Mutex // защищает pending и nextID
	nextID  uint16
	pending map[uint16]*pending
}

func newProxy(listen, upstream string) (*proxy, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &proxy{
		upstream: upstream,
		udpConn:  udpConn,
		pending:  make(map[uint16]*pending),
	}, nil
}

// getConn возвращает живое TCP-соединение к upstream, при необходимости
// устанавливая новое и запуская для него readLoop.
func (p *proxy) getConn() (net.Conn, error) {
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	if p.tcpConn != nil {
		return p.tcpConn, nil
	}
	conn, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		return nil, err
	}
	p.tcpConn = conn
	go p.readLoop(conn)
	log.Printf("upstream: подключились к %s", p.upstream)
	return conn, nil
}

func (p *proxy) dropConn(conn net.Conn) {
	p.dialMu.Lock()
	if p.tcpConn == conn {
		p.tcpConn = nil
	}
	p.dialMu.Unlock()
	conn.Close()
}

func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

// readLoop постоянно читает из TCP-соединения ответы формата
// DNS-over-TCP (2 байта длины + сообщение) и раздаёт их обратно
// исходным UDP-клиентам по сохранённому в pending маппингу ID.
func (p *proxy) readLoop(conn net.Conn) {
	defer p.dropConn(conn)
	lenBuf := make([]byte, 2)
	for {
		if err := readFull(conn, lenBuf); err != nil {
			log.Printf("upstream: соединение разорвано: %v", err)
			return
		}
		n := binary.BigEndian.Uint16(lenBuf)
		msg := make([]byte, n)
		if err := readFull(conn, msg); err != nil {
			log.Printf("upstream: соединение разорвано: %v", err)
			return
		}
		if len(msg) < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(msg[0:2])

		p.mu.Lock()
		pend, ok := p.pending[id]
		if ok {
			delete(p.pending, id)
		}
		p.mu.Unlock()
		if !ok {
			// ответ на уже истёкший по таймауту запрос — просто игнорируем
			continue
		}
		pend.timer.Stop()
		binary.BigEndian.PutUint16(msg[0:2], pend.origID)
		if _, err := p.udpConn.WriteToUDP(msg, pend.clientAddr); err != nil {
			log.Printf("udp write error: %v", err)
		}
	}
}

func (p *proxy) serve() {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := p.udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("udp read error: %v", err)
			continue
		}
		if n < 2 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go p.handleQuery(query, clientAddr)
	}
}

func (p *proxy) handleQuery(query []byte, clientAddr *net.UDPAddr) {
	origID := binary.BigEndian.Uint16(query[0:2])

	p.mu.Lock()
	newID := p.nextID
	for {
		if _, exists := p.pending[newID]; !exists {
			break
		}
		newID++
	}
	p.nextID = newID + 1
	binary.BigEndian.PutUint16(query[0:2], newID)

	timer := time.AfterFunc(5*time.Second, func() {
		p.mu.Lock()
		delete(p.pending, newID)
		p.mu.Unlock()
	})
	p.pending[newID] = &pending{clientAddr: clientAddr, origID: origID, timer: timer}
	p.mu.Unlock()

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(query)))
	copy(frame[2:], query)

	// Одна попытка + один реконнект, если соединение оказалось мёртвым
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := p.getConn()
		if err != nil {
			log.Printf("upstream dial error: %v", err)
			break
		}
		p.dialMu.Lock()
		_, werr := conn.Write(frame)
		p.dialMu.Unlock()
		if werr == nil {
			return
		}
		log.Printf("upstream write error (попытка %d): %v", attempt+1, werr)
		p.dropConn(conn)
	}

	p.mu.Lock()
	delete(p.pending, newID)
	p.mu.Unlock()
}

func main() {
	listen := flag.String("listen", "127.0.0.1:53", "UDP-адрес для приёма запросов от системы")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream DNS-сервер, TCP:53")
	flag.Parse()

	p, err := newProxy(*listen, *upstream)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("dns-tcp-proxy: слушаю %s (udp) -> пересылаю %s (tcp)", *listen, *upstream)
	p.serve()
}
