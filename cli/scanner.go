package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNS record types
const (
	dnsTypeA   = 1
	dnsTypeNS  = 2
	dnsTypeTXT = 16
	dnsTypeOPT = 41
)

// Scanner result status
const (
	statusWorking = "WORKING"
	statusTimeout = "TIMEOUT"
	statusError   = "ERROR"
)

// TunnelTestResult holds detailed DNS tunnel compatibility results.
type TunnelTestResult struct {
	NSSupport      bool
	TXTSupport     bool
	RandomSub      bool
	TunnelRealism  bool
	EDNS0Support   bool
	EDNSMaxPayload int
	NXDOMAINCorrect bool
}

func (t *TunnelTestResult) Score() int {
	n := 0
	for _, b := range []bool{t.NSSupport, t.TXTSupport, t.RandomSub, t.TunnelRealism, t.EDNS0Support, t.NXDOMAINCorrect} {
		if b {
			n++
		}
	}
	return n
}

func (t *TunnelTestResult) Details() string {
	f := func(ok bool, label string) string {
		if ok {
			return label + "✓"
		}
		return label + "✗"
	}
	edns := f(t.EDNS0Support, "EDNS")
	if t.EDNS0Support && t.EDNSMaxPayload > 0 {
		edns += fmt.Sprintf("(%d)", t.EDNSMaxPayload)
	}
	return fmt.Sprintf("%s %s %s %s %s %s",
		f(t.NSSupport, "NS→A"), f(t.TXTSupport, "TXT"), f(t.RandomSub, "RND"),
		f(t.TunnelRealism, "DPI"), edns, f(t.NXDOMAINCorrect, "NXD"))
}

// ScanResult holds the result of scanning one resolver.
type ScanResult struct {
	Host       string
	Port       int
	Status     string
	LatencyMs  int64
	Error      string
	Tunnel     *TunnelTestResult
}

// ScanResolvers scans a list of resolver IPs concurrently, supporting dynamic expansion.
func ScanResolvers(initialResolvers []string, port int, testDomain string, timeoutMs int, concurrency int, expandNeighbors bool, onResult func(ScanResult, int, int)) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	var scannedCount int32
	var totalCount int32 = int32(len(initialResolvers))

	seen := make(map[string]bool)
	var mu sync.Mutex
	for _, ip := range initialResolvers {
		seen[ip] = true
	}

	expandedSubnets := make(map[string]bool)
	taskCh := make(chan string, 100000)

	// Start workers first to prevent deadlock if initial list > buffer size
	for i := 0; i < concurrency; i++ {
		go func() {
			for host := range taskCh {
				sem <- struct{}{}
				result := scanResolver(host, port, testDomain, timeoutMs)
				<-sem

				sc := atomic.AddInt32(&scannedCount, 1)

				if expandNeighbors && result.Status == statusWorking {
					subnet := getSubnet(host)
					mu.Lock()
					if subnet != "" && !expandedSubnets[subnet] {
						expandedSubnets[subnet] = true
						neighbors := ExpandSlash24(host)
						var toAdd []string
						for _, n := range neighbors {
							if !seen[n] {
								seen[n] = true
								toAdd = append(toAdd, n)
							}
						}
						mu.Unlock()

						for _, n := range toAdd {
							atomic.AddInt32(&totalCount, 1)
							wg.Add(1)
							taskCh <- n
						}
					} else {
						mu.Unlock()
					}
				}

				tc := atomic.LoadInt32(&totalCount)
				onResult(result, int(sc), int(tc))
				wg.Done()
			}
		}()
	}

	// Feed initial resolvers
	wg.Add(len(initialResolvers))
	go func() {
		for _, ip := range initialResolvers {
			taskCh <- ip
		}
	}()

	wg.Wait()
	close(taskCh)
}

func getSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return ""
}

func scanResolver(host string, port int, testDomain string, timeoutMs int) ScanResult {
	result := ScanResult{Host: host, Port: port}

	start := time.Now()
	sub := randomLabel(8)
	parent := getParentDomain(testDomain)
	query := sub + "." + parent

	// Use shorter timeout for initial probe
	probeTimeout := timeoutMs
	if probeTimeout > 1500 {
		probeTimeout = 1500
	}
	resp, err := dnsQuery(host, port, query, dnsTypeA, probeTimeout, nil)
	latency := time.Since(start).Milliseconds()
	result.LatencyMs = latency

	if err != nil {
		if isTimeout(err) {
			result.Status = statusTimeout
		} else {
			result.Status = statusError
			result.Error = err.Error()
		}
		return result
	}
	if resp == nil {
		result.Status = statusTimeout
		return result
	}

	result.Status = statusWorking
	tunnel := &TunnelTestResult{}

	// Run all tunnel tests concurrently for speed
	var twg sync.WaitGroup
	twg.Add(6)
	go func() { defer twg.Done(); tunnel.NSSupport = testNS(host, port, parent, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.TXTSupport = testTXT(host, port, testDomain, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.RandomSub = testRandomSubdomain(host, port, testDomain, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.TunnelRealism = testTunnelRealism(host, port, testDomain, timeoutMs) }()
	go func() {
		defer twg.Done()
		tunnel.EDNS0Support, tunnel.EDNSMaxPayload = testEDNS0(host, port, testDomain, timeoutMs)
	}()
	go func() { defer twg.Done(); tunnel.NXDOMAINCorrect = testNXDOMAIN(host, port, timeoutMs) }()
	twg.Wait()

	result.Tunnel = tunnel
	return result
}

// --- Individual tests ---

func testNS(host string, port int, parentDomain string, timeoutMs int) bool {
	resp, err := dnsQuery(host, port, parentDomain, dnsTypeNS, timeoutMs, nil)
	if err != nil || resp == nil {
		return false
	}
	nsHost := extractNSHost(resp)
	if nsHost == "" {
		return false
	}
	// Resolve the NS hostname via A record
	resp2, err := dnsQuery(host, port, nsHost, dnsTypeA, timeoutMs, nil)
	return err == nil && resp2 != nil
}

func testTXT(host string, port int, testDomain string, timeoutMs int) bool {
	sub := randomLabel(8)
	parent := getParentDomain(testDomain)
	resp, err := dnsQuery(host, port, sub+"."+parent, dnsTypeTXT, timeoutMs, nil)
	return err == nil && resp != nil
}

func testRandomSubdomain(host string, port int, testDomain string, timeoutMs int) bool {
	for i := 0; i < 2; i++ {
		sub := randomLabel(8) + "." + randomLabel(8)
		resp, err := dnsQuery(host, port, sub+"."+testDomain, dnsTypeA, timeoutMs, nil)
		if err == nil && resp != nil {
			return true
		}
	}
	return false
}

func testTunnelRealism(host string, port int, testDomain string, timeoutMs int) bool {
	// Generate 100 random bytes, base32-encode, split into 57-char DNS labels
	randBytes := make([]byte, 100)
	for i := range randBytes {
		randBytes[i] = byte(rand.IntN(256))
	}
	encoded := base32Encode(randBytes)
	labels := splitLabels(encoded, 57)
	query := strings.Join(labels, ".") + "." + testDomain

	resp, err := dnsQuery(host, port, query, dnsTypeTXT, timeoutMs, nil)
	return err == nil && resp != nil
}

func testEDNS0(host string, port int, testDomain string, timeoutMs int) (bool, int) {
	sizes := []int{512, 900, 1232}
	maxPayload := 0
	anyOK := false
	for _, size := range sizes {
		sub := randomLabel(8)
		parent := getParentDomain(testDomain)
		query := sub + "." + parent

		edns := buildEDNS0OPT(size)
		resp, err := dnsQuery(host, port, query, dnsTypeA, timeoutMs, edns)
		if err != nil || resp == nil {
			break
		}
		// Check if response contains OPT record and RCODE != FORMERR(1)
		rcode := int(resp[3]) & 0x0F
		if rcode == 1 { // FORMERR
			break
		}
		if hasOPTRecord(resp) {
			anyOK = true
			maxPayload = size
		} else {
			break
		}
	}
	return anyOK, maxPayload
}

func testNXDOMAIN(host string, port int, timeoutMs int) bool {
	good := 0
	for i := 0; i < 3; i++ {
		sub := randomLabel(12)
		query := sub + ".invalid"
		resp, err := dnsQuery(host, port, query, dnsTypeA, timeoutMs, nil)
		if err != nil || resp == nil {
			continue
		}
		rcode := int(resp[3]) & 0x0F
		if rcode == 3 { // NXDOMAIN
			good++
		}
	}
	return good >= 2
}

// DetectTransparentProxy tests if the ISP intercepts DNS queries
func DetectTransparentProxy(testDomain string, timeoutMs int) bool {
	testNets := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	var detected atomic.Bool
	var wg sync.WaitGroup
	for _, ip := range testNets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sub := randomLabel(8)
			resp, err := dnsQuery(ip, 53, sub+"."+testDomain, dnsTypeA, timeoutMs, nil)
			if err == nil && resp != nil {
				detected.Store(true)
			}
		}(ip)
	}
	wg.Wait()
	return detected.Load()
}

// --- DNS packet construction & parsing ---

func dnsQuery(host string, port int, name string, qtype uint16, timeoutMs int, additional []byte) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	txid := []byte{byte(rand.IntN(256)), byte(rand.IntN(256))}

	var pkt []byte
	pkt = append(pkt, txid...)
	pkt = append(pkt, 0x01, 0x00) // flags: RD=1
	pkt = append(pkt, 0x00, 0x01) // questions: 1
	pkt = append(pkt, 0x00, 0x00) // answers: 0
	pkt = append(pkt, 0x00, 0x00) // authority: 0
	if additional != nil {
		pkt = append(pkt, 0x00, 0x01) // additional: 1
	} else {
		pkt = append(pkt, 0x00, 0x00) // additional: 0
	}

	pkt = append(pkt, encodeDNSName(name)...)
	pkt = append(pkt, byte(qtype>>8), byte(qtype))
	pkt = append(pkt, 0x00, 0x01) // IN class

	if additional != nil {
		pkt = append(pkt, additional...)
	}

	_, err = conn.Write(pkt)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	return out
}

func buildEDNS0OPT(payloadSize int) []byte {
	return []byte{
		0x00,
		0x00, byte(dnsTypeOPT),
		byte(payloadSize >> 8), byte(payloadSize),
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}

func hasOPTRecord(resp []byte) bool {
	if len(resp) < 12 {
		return false
	}
	arcount := int(binary.BigEndian.Uint16(resp[10:12]))
	if arcount == 0 {
		return false
	}
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	nscount := int(binary.BigEndian.Uint16(resp[8:10]))

	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4
	}
	for i := 0; i < ancount+nscount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return false
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	for i := 0; i < arcount && offset < len(resp); i++ {
		nameEnd := skipDNSName(resp, offset)
		if nameEnd+10 > len(resp) {
			return false
		}
		rtype := binary.BigEndian.Uint16(resp[nameEnd : nameEnd+2])
		if rtype == dnsTypeOPT {
			return true
		}
		rdlen := int(binary.BigEndian.Uint16(resp[nameEnd+8 : nameEnd+10]))
		offset = nameEnd + 10 + rdlen
	}
	return false
}

func extractNSHost(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4
	}
	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == dnsTypeNS && rdlen > 0 && offset+rdlen <= len(resp) {
			return decodeDNSName(resp, offset)
		}
		offset += rdlen
	}
	return ""
}

func skipDNSName(pkt []byte, offset int) int {
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xC0 {
			return offset + 2
		}
		offset += 1 + length
	}
	return offset
}

func decodeDNSName(pkt []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool)
	for offset < len(pkt) {
		if visited[offset] {
			break
		}
		visited[offset] = true
		length := int(pkt[offset])
		if length == 0 {
			break
		}
		if length >= 0xC0 {
			if offset+1 >= len(pkt) {
				break
			}
			ptr := int(pkt[offset]&0x3F)<<8 | int(pkt[offset+1])
			offset = ptr
			continue
		}
		offset++
		if offset+length > len(pkt) {
			break
		}
		parts = append(parts, string(pkt[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ".")
}

// --- Utilities ---

func getParentDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) >= 2 && strings.Contains(parts[1], ".") {
		return parts[1]
	}
	return domain
}

func randomLabel(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.IntN(len(chars))]
	}
	return string(b)
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	var sb strings.Builder
	buf := uint64(0)
	bits := 0
	for _, b := range data {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			idx := (buf >> uint(bits)) & 0x1F
			sb.WriteByte(base32Alphabet[idx])
		}
	}
	if bits > 0 {
		idx := (buf << uint(5-bits)) & 0x1F
		sb.WriteByte(base32Alphabet[idx])
	}
	return sb.String()
}

func splitLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > maxLen {
		labels = append(labels, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		labels = append(labels, s)
	}
	return labels
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// LoadIPList parses a text file/string into a list of IP addresses.
func LoadIPList(content string) []string {
	var ips []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		ip := strings.Split(parts[0], ":")[0]
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// RunScanner is the main entry point for the CLI scanner.
func RunScanner(resolvers []string, testDomain string, port int, timeoutMs int, concurrency int, expandNeighbors bool, e2eConfig *E2EConfig, useTUI bool) {
	total := len(resolvers)
	var scanned int64
	var working int64
	var timeouts int64
	var errors int64

	type scoredResult struct {
		ScanResult
		score int
	}
	var mu sync.Mutex
	var compatible []scoredResult

	updateCh := make(chan ScannerMsg, 100)
	if useTUI {
		go RunTUI(testDomain, updateCh)
		go func() {
			detected := DetectTransparentProxy(testDomain, 2000)
			updateCh <- ScannerMsg{ProxyChecked: true, ProxyDetected: detected}
		}()
	} else {
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════╗")
		fmt.Println("║              SlipNet DNS Scanner                 ║")
		fmt.Println("╚══════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Printf("  Domain:      %s\n", testDomain)
		fmt.Printf("  Resolvers:   %d\n", total)
		fmt.Printf("  Concurrency: %d\n", concurrency)
		fmt.Printf("  Timeout:     %dms\n", timeoutMs)
		fmt.Println()

		fmt.Print("  Checking for transparent DNS proxy... ")
		if DetectTransparentProxy(testDomain, 2000) {
			fmt.Println("DETECTED")
			fmt.Println("  ⚠ Your ISP intercepts DNS queries. Results may be inaccurate.")
		} else {
			fmt.Println("not detected")
		}
		fmt.Println()
	}

	startTime := time.Now()

	ScanResolvers(resolvers, port, testDomain, timeoutMs, concurrency, expandNeighbors, func(r ScanResult, currentScanned int, currentTotal int) {
		atomic.StoreInt64(&scanned, int64(currentScanned))
		n := int64(currentScanned)

		switch r.Status {
		case statusWorking:
			atomic.AddInt64(&working, 1)
		case statusTimeout:
			atomic.AddInt64(&timeouts, 1)
		case statusError:
			atomic.AddInt64(&errors, 1)
		}

		if r.Tunnel != nil && r.Tunnel.Score() > 0 {
			mu.Lock()
			compatible = append(compatible, scoredResult{r, r.Tunnel.Score()})
			mu.Unlock()
		}

		if useTUI {
			updateCh <- ScannerMsg{
				Result:         &r,
				Scanned:        int(n),
				Total:          currentTotal,
				Working:        int(atomic.LoadInt64(&working)),
				ExpansionQueue: currentTotal - int(n),
			}
		} else {
			if n%10 == 0 || n == int64(currentTotal) {
				w := atomic.LoadInt64(&working)
				fmt.Printf("\r  Scanning... %d/%d  (working: %d)", n, currentTotal, w)
			}
		}
	})

	if useTUI {
		updateCh <- ScannerMsg{Done: true}
		time.Sleep(100 * time.Millisecond)
	}

	elapsed := time.Since(startTime)
	if !useTUI {
		fmt.Printf("\r  Scanning... %d/%d  (working: %d)\n", atomic.LoadInt64(&scanned), atomic.LoadInt64(&scanned), atomic.LoadInt64(&working))
		fmt.Println()
	}

	mu.Lock()
	for i := 0; i < len(compatible); i++ {
		for j := i + 1; j < len(compatible); j++ {
			if compatible[j].score > compatible[i].score ||
				(compatible[j].score == compatible[i].score && compatible[j].LatencyMs < compatible[i].LatencyMs) {
				compatible[i], compatible[j] = compatible[j], compatible[i]
			}
		}
	}
	mu.Unlock()

	fmt.Println("  ── Results ──────────────────────────────────────")
	fmt.Println()
	fmt.Printf("  Total Scanned: %d | Working: %d | Timeout: %d | Error: %d\n",
		atomic.LoadInt64(&scanned), atomic.LoadInt64(&working), atomic.LoadInt64(&timeouts), atomic.LoadInt64(&errors))
	fmt.Printf("  Elapsed: %s\n", elapsed.Round(time.Millisecond))
	fmt.Println()

	if len(compatible) == 0 {
		fmt.Println("  No compatible resolvers found.")
		return
	}

	fmt.Printf("  Compatible resolvers (%d):\n\n", len(compatible))
	fmt.Printf("  %-18s %5s  %5s  %s\n", "RESOLVER", "SCORE", "MS", "DETAILS")
	fmt.Printf("  %-18s %5s  %5s  %s\n", "────────────────", "─────", "─────", "──────────────────────────────")

	for _, r := range compatible {
		marker := " "
		if r.score == 6 {
			marker = "*"
		}
		fmt.Printf(" %s%-18s %d/6    %4dms  %s\n",
			marker, r.Host, r.score, r.LatencyMs, r.Tunnel.Details())
	}
	fmt.Println()
	fmt.Println("  * = fully compatible (6/6)")
	fmt.Println()

	var top []string
	for _, r := range compatible {
		if r.score == 6 {
			top = append(top, r.Host)
		}
		if len(top) >= 10 {
			break
		}
	}
	if len(top) > 0 {
		fmt.Printf("  Top resolvers (copy-paste ready):\n  %s\n", strings.Join(top, ","))
		fmt.Println()
	}

	if e2eConfig != nil && len(top) > 0 {
		runE2EPhase(top, e2eConfig)
	}
}

func runE2EPhase(resolvers []string, config *E2EConfig) {
	fmt.Println("  ── E2E Tunnel Test ──────────────────────────────")
	fmt.Println()
	fmt.Printf("  Testing %d resolvers through real tunnel...\n", len(resolvers))
	fmt.Println("  Mode: DNSTT")
	fmt.Println()

	total := len(resolvers)
	var tested int64
	var passed int64

	type e2eEntry struct {
		E2EResult
	}
	var mu sync.Mutex
	var results []e2eEntry

	e2eStart := time.Now()

	RunE2ETests(resolvers, *config, func(r E2EResult) {
		n := atomic.AddInt64(&tested, 1)
		if r.Success {
			atomic.AddInt64(&passed, 1)
		}

		mu.Lock()
		results = append(results, e2eEntry{r})
		mu.Unlock()

		status := "PASS"
		detail := fmt.Sprintf("%dms", r.TotalMs)
		if !r.Success {
			status = "FAIL"
			detail = r.Error
		}
		fmt.Printf("\r  [%d/%d] %-18s %s  %s\n", n, total, r.Host, status, detail)
	})

	e2eElapsed := time.Since(e2eStart)

	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			ri, rj := results[i], results[j]
			if (!ri.Success && rj.Success) ||
				(ri.Success == rj.Success && ri.TotalMs > rj.TotalMs) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	fmt.Println()
	fmt.Printf("  E2E: %d/%d passed (%s)\n", passed, total, e2eElapsed.Round(time.Millisecond))
	fmt.Println()

	if passed == 0 {
		fmt.Println("  No resolvers passed E2E test.")
		fmt.Println()
		return
	}

	fmt.Printf("  %-18s %7s  %7s  %7s  %s\n", "RESOLVER", "TUNNEL", "HTTP", "TOTAL", "STATUS")
	fmt.Printf("  %-18s %7s  %7s  %7s  %s\n", "────────────────", "───────", "───────", "───────", "──────")

	for _, r := range results {
		if r.Success {
			fmt.Printf("  %-18s %5dms  %5dms  %5dms  PASS\n",
				r.Host, r.TunnelMs, r.HTTPMs, r.TotalMs)
		} else {
			fmt.Printf("  %-18s %7s  %7s  %5dms  FAIL: %s\n",
				r.Host, "-", "-", r.TotalMs, r.Error)
		}
	}
	fmt.Println()

	var passedIPs []string
	for _, r := range results {
		if r.Success {
			passedIPs = append(passedIPs, r.Host)
		}
	}
	if len(passedIPs) > 0 {
		fmt.Printf("  E2E verified resolvers:\n  %s\n", strings.Join(passedIPs, ","))
		fmt.Println()
	}
}
