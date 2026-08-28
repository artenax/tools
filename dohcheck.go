// dohcheck.go
//
// Простая утилита DoH (DNS over HTTPS) резолвер.
// Основная цель — не резолвинг сам по себе, а проверка того,
// блокирует ли провайдер доступ к конкретному DoH-серверу.
//
// Использование:
//   app <домен> +<doh-резолвер>
//
// Примеры:
//   app example.com +dns.google
//   app example.com +8.8.8.8
//   app +1.1.1.1 example.com   (порядок аргументов не важен)
//
// Сборка (в Termux):
//   go build -o dohcheck dohcheck.go
//   ./dohcheck example.com +dns.google

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	dnsPath        = "/dns-query"
	connectTimeout = 30 * time.Second
)

// Известные IP-адреса публичных DoH-серверов -> имя хоста для
// SNI / заголовка Host (нужно, т.к. TLS-сертификат выдан на имя,
// а не на IP).
var knownDoHHosts = map[string]string{
	"8.8.8.8":              "dns.google",
	"8.8.4.4":              "dns.google",
	"2001:4860:4860::8888": "dns.google",
	"2001:4860:4860::8844": "dns.google",

	"1.1.1.1":              "cloudflare-dns.com",
	"1.0.0.1":              "cloudflare-dns.com",
	"2606:4700:4700::1111": "cloudflare-dns.com",
	"2606:4700:4700::1001": "cloudflare-dns.com",

	"9.9.9.9":         "dns.quad9.net",
	"149.112.112.112": "dns.quad9.net",

	"208.67.222.222": "doh.opendns.com",
	"208.67.220.220": "doh.opendns.com",

	"94.140.14.14": "dns.adguard-dns.com",
	"94.140.15.15": "dns.adguard-dns.com",
}

func main() {
	domain, resolver, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка аргументов:", err)
		fmt.Fprintln(os.Stderr, "Использование: app <домен> +<doh-резолвер>")
		fmt.Fprintln(os.Stderr, "Пример: app example.com +dns.google")
		os.Exit(1)
	}

	targetHost, sniHost, insecure := resolveEndpoint(resolver)

	reqURL := buildURL(targetHost)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: insecure,
		},
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: connectTimeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   connectTimeout,
	}

	fmt.Printf("Домен:        %s\n", domain)
	fmt.Printf("DoH-резолвер: %s\n", resolver)
	fmt.Printf("URL запроса:  %s\n", reqURL)
	if insecure {
		fmt.Println("Предупреждение: IP неизвестен списку известных DoH-провайдеров,")
		fmt.Println("проверка TLS-сертификата отключена (InsecureSkipVerify).")
	}
	fmt.Println(strings.Repeat("-", 40))

	var allIPs []net.IP
	var totalDur time.Duration
	successCount := 0

	queries := []struct {
		label string
		qtype uint16
	}{
		{"A (IPv4)", 1},
		{"AAAA (IPv6)", 28},
	}

	for _, q := range queries {
		ips, dur, err := doDoHQuery(client, reqURL, sniHost, domain, q.qtype)
		totalDur += dur
		if err != nil {
			fmt.Printf("[%s] ошибка (%v): %s\n", q.label, dur.Round(time.Millisecond), describeError(err))
			continue
		}
		successCount++
		fmt.Printf("[%s] запрос выполнен за %v, записей: %d\n", q.label, dur.Round(time.Millisecond), len(ips))
		allIPs = append(allIPs, ips...)
	}

	fmt.Println(strings.Repeat("-", 40))

	if successCount == 0 {
		fmt.Println("Не удалось получить ответ ни на один запрос — DoH-сервер, вероятно, недоступен/заблокирован.")
		os.Exit(1)
	}

	if len(allIPs) == 0 {
		fmt.Println("Адреса не найдены (NXDOMAIN либо домен не имеет A/AAAA записей).")
	} else {
		fmt.Println("Адреса:")
		for _, ip := range allIPs {
			fmt.Println(" ", ip.String())
		}
	}
	fmt.Printf("\nОбщее время DNS-запросов: %v\n", totalDur.Round(time.Millisecond))
}

// parseArgs находит среди аргументов домен и резолвер (начинается с '+'),
// не завися от их порядка.
func parseArgs(args []string) (domain string, resolver string, err error) {
	for _, a := range args {
		if strings.HasPrefix(a, "+") {
			if resolver != "" {
				return "", "", errors.New("указано несколько DoH-резолверов")
			}
			resolver = strings.TrimPrefix(a, "+")
		} else {
			if domain != "" {
				return "", "", errors.New("указано несколько доменов")
			}
			domain = a
		}
	}
	if domain == "" {
		return "", "", errors.New("не указан домен")
	}
	if resolver == "" {
		return "", "", errors.New("не указан DoH-резолвер (формат +host или +ip)")
	}
	return domain, resolver, nil
}

// resolveEndpoint возвращает: адрес для подключения, имя для SNI/Host,
// и флаг отключения проверки сертификата (для неизвестных IP).
func resolveEndpoint(resolver string) (targetHost, sniHost string, insecure bool) {
	if ip := net.ParseIP(resolver); ip != nil {
		targetHost = resolver
		if known, ok := knownDoHHosts[resolver]; ok {
			sniHost = known
		} else {
			sniHost = resolver
			insecure = true
		}
		return
	}
	// это доменное имя
	targetHost = resolver
	sniHost = resolver
	return
}

func buildURL(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// IPv6 литерал нужно заключать в скобки
		return fmt.Sprintf("https://[%s]%s", host, dnsPath)
	}
	return fmt.Sprintf("https://%s%s", host, dnsPath)
}

// buildQuery строит "сырое" DNS-сообщение (RFC 1035) для одного вопроса.
func buildQuery(name string, qtype uint16) []byte {
	var buf bytes.Buffer

	id := uint16(rand.Intn(65536))
	binary.Write(&buf, binary.BigEndian, id)
	binary.Write(&buf, binary.BigEndian, uint16(0x0100)) // стандартный запрос, RD=1
	binary.Write(&buf, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ARCOUNT

	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // конец имени

	binary.Write(&buf, binary.BigEndian, qtype)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // класс IN

	return buf.Bytes()
}

// skipName пропускает имя (в вопросе или ответе), учитывая сжатие (указатели).
func skipName(msg []byte, offset int) (int, error) {
	steps := 0
	for {
		if offset >= len(msg) {
			return 0, errors.New("некорректное имя в ответе (offset за пределами)")
		}
		l := msg[offset]
		switch {
		case l&0xC0 == 0xC0: // указатель на 2 байта
			return offset + 2, nil
		case l == 0:
			return offset + 1, nil
		default:
			offset += int(l) + 1
		}
		steps++
		if steps > 128 {
			return 0, errors.New("слишком длинное или зацикленное имя в ответе")
		}
	}
}

// parseResponse разбирает сырое DNS-сообщение и возвращает найденные IP.
func parseResponse(msg []byte) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("слишком короткий ответ DNS")
	}

	rcode := msg[3] & 0x0F
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])

	offset := 12
	for i := 0; i < int(qdcount); i++ {
		var err error
		offset, err = skipName(msg, offset)
		if err != nil {
			return nil, err
		}
		offset += 4 // QTYPE + QCLASS
	}

	if rcode != 0 {
		return nil, fmt.Errorf("DNS-сервер вернул код ошибки RCODE=%d", rcode)
	}

	var ips []net.IP
	for i := 0; i < int(ancount); i++ {
		var err error
		offset, err = skipName(msg, offset)
		if err != nil {
			return nil, err
		}
		if offset+10 > len(msg) {
			return nil, errors.New("повреждённая запись ответа")
		}
		rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(msg[offset+8 : offset+10])
		offset += 10
		if offset+int(rdlength) > len(msg) {
			return nil, errors.New("повреждённые данные записи (rdata)")
		}
		rdata := msg[offset : offset+int(rdlength)]

		switch rtype {
		case 1: // A
			if len(rdata) == 4 {
				ips = append(ips, net.IP(rdata))
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				ips = append(ips, net.IP(rdata))
			}
		}
		offset += int(rdlength)
	}

	return ips, nil
}

// doDoHQuery отправляет один DNS-запрос по HTTPS (RFC 8484, POST-метод)
// и возвращает найденные адреса и время выполнения запроса.
func doDoHQuery(client *http.Client, url, hostHeader, name string, qtype uint16) ([]net.IP, time.Duration, error) {
	query := buildQuery(name, qtype)

	req, err := http.NewRequest("POST", url, bytes.NewReader(query))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if hostHeader != "" {
		req.Host = hostHeader
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, elapsed, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, elapsed, fmt.Errorf("HTTP %d от сервера: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	ips, err := parseResponse(body)
	return ips, elapsed, err
}

// describeError пытается дать более понятное объяснение причины ошибки —
// это и есть основная диагностическая часть утилиты.
func describeError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "ТАЙМАУТ соединения (похоже на блокировку/фильтрацию трафика провайдером) — " + err.Error()
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "таймаут при резолвинге имени резолвера — " + err.Error()
		}
		if dnsErr.IsNotFound {
			return "имя DoH-резолвера не резолвится (NXDOMAIN) — " + err.Error()
		}
		return "ошибка резолвинга имени резолвера — " + err.Error()
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "ошибка сетевого соединения (" + opErr.Op + ") — " + err.Error()
	}

	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return "ошибка проверки TLS-сертификата — " + err.Error()
	}

	return err.Error()
}
