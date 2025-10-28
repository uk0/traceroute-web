package main

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

//go:embed templates/index.html
var tplIndex string

//go:embed templates/result.html
var tplResult string

//go:embed static/app.css
var cssContent string

var (
	tplIndexParsed  = template.Must(template.New("index").Parse(tplIndex))
	tplResultParsed = template.Must(template.New("result").Parse(tplResult))
)

// =================== 配置 ===================

type Config struct {
	ListenAddr     string
	MaxHops        int
	Count          int
	TimeoutMS      int
	GeoASNPath     string
	GeoCityPath    string
	GeoCountryPath string
}

var cfg = Config{
	ListenAddr:     ":8080",
	MaxHops:        30,
	Count:          3,
	TimeoutMS:      1000,
	GeoASNPath:     "./GeoLite2-ASN.mmdb",
	GeoCityPath:    "./GeoLite2-City.mmdb",
	GeoCountryPath: "./GeoLite2-Country.mmdb",
}

type Mode string

const (
	ModeICMP Mode = "icmp"
	ModeTCP  Mode = "tcp"
	ModeUDP  Mode = "udp"
)

// =================== GeoDB ===================

type GeoDB struct {
	asn     *geoip2.Reader
	city    *geoip2.Reader
	country *geoip2.Reader
	mu      sync.RWMutex
}

func (g *GeoDB) Open() {
	var err error
	if fileExists(cfg.GeoASNPath) {
		if g.asn, err = geoip2.Open(cfg.GeoASNPath); err != nil {
			log.Printf("warn: open ASN DB failed: %v", err)
		}
	}
	if fileExists(cfg.GeoCityPath) {
		if g.city, err = geoip2.Open(cfg.GeoCityPath); err != nil {
			log.Printf("warn: open City DB failed: %v", err)
		}
	}
	if fileExists(cfg.GeoCountryPath) {
		if g.country, err = geoip2.Open(cfg.GeoCountryPath); err != nil {
			log.Printf("warn: open Country DB failed: %v", err)
		}
	}
}

func (g *GeoDB) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.asn != nil {
		g.asn.Close()
	}
	if g.city != nil {
		g.city.Close()
	}
	if g.country != nil {
		g.country.Close()
	}
}

func (g *GeoDB) Lookup(ip net.IP) (geo string, as string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if ip == nil {
		return "--", "--"
	}

	// ASN
	if g.asn != nil {
		if rec, err := g.asn.ASN(ip); err == nil && rec != nil && rec.AutonomousSystemNumber != 0 {
			asName := rec.AutonomousSystemOrganization
			as = fmt.Sprintf("AS%d %s", rec.AutonomousSystemNumber, asName)
		}
	}

	// City / Country
	countryName := ""
	cityName := ""
	if g.city != nil {
		if rec, err := g.city.City(ip); err == nil && rec != nil {
			if rec.Country.Names != nil {
				if cn, ok := rec.Country.Names["zh-CN"]; ok && cn != "" {
					countryName = cn
				} else if en, ok := rec.Country.Names["en"]; ok {
					countryName = en
				}
			}
			if rec.City.Names != nil {
				if cn, ok := rec.City.Names["zh-CN"]; ok && cn != "" {
					cityName = cn
				} else if en, ok := rec.City.Names["en"]; ok {
					cityName = en
				}
			}
		}
	}
	if countryName == "" && g.country != nil {
		if rec, err := g.country.Country(ip); err == nil && rec != nil && rec.Country.Names != nil {
			if cn, ok := rec.Country.Names["zh-CN"]; ok && cn != "" {
				countryName = cn
			} else if en, ok := rec.Country.Names["en"]; ok {
				countryName = en
			}
		}
	}

	if countryName == "" && cityName == "" {
		geo = "--"
	} else if countryName != "" && cityName != "" {
		geo = countryName + " / " + cityName
	} else {
		geo = countryName + cityName
	}

	if as == "" {
		as = "--"
	}
	return geo, as
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// =================== 数据结构 ===================

type HopStat struct {
	Hop       int      `json:"hop"`
	IPs       []string `json:"ips"`
	Hostnames []string `json:"hostnames"`
	Sent      int      `json:"sent"`
	LossPct   float64  `json:"loss_pct"`
	LastMS    int      `json:"last_ms"`
	BestMS    int      `json:"best_ms"`
	WorstMS   int      `json:"worst_ms"`
	AvgMS     int      `json:"avg_ms"`
	Reachable bool     `json:"reachable"`
	Geos      []string `json:"geos"`
	ASes      []string `json:"ases"`
}

type TraceParams struct {
	Target    string
	Mode      Mode
	DPort     uint16
	MaxHops   int
	Count     int
	TimeoutMS int
}

type ProbeResult struct {
	TTL      int
	Seq      int
	IP       string
	RTT      time.Duration
	Type     string
	Received bool
}

// =================== HTTP ===================

func main() {
	geoDB.Open()
	defer geoDB.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/trace", tracePageHandler)
	mux.HandleFunc("/stream", streamHandler)
	mux.HandleFunc("/static/app.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(cssContent))
	})

	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}

var geoDB GeoDB

func isRoot() bool {
	return os.Geteuid() == 0
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	_ = tplIndexParsed.Execute(w, map[string]any{
		"defaultMaxHops": cfg.MaxHops,
		"defaultCount":   cfg.Count,
		"defaultTimeout": cfg.TimeoutMS,
		"tcpNeedRoot":    !isRoot(),
	})
}

func tracePageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	target := strings.TrimSpace(r.FormValue("target"))
	if target == "" {
		http.Error(w, "target required", 400)
		return
	}
	mode := Mode(strings.ToLower(r.FormValue("mode")))
	if mode != ModeICMP && mode != ModeTCP && mode != ModeUDP {
		mode = ModeICMP
	}
	maxHops := parseInt(r.FormValue("maxhops"), 1, 64, cfg.MaxHops)
	count := parseInt(r.FormValue("count"), 1, 10, cfg.Count)
	timeout := parseInt(r.FormValue("timeout"), 300, 5000, cfg.TimeoutMS)
	dport := uint16(parseInt(r.FormValue("dport"), 1, 65535, 33434))

	_ = tplResultParsed.Execute(w, map[string]any{
		"Target":  target,
		"Mode":    string(mode),
		"DPort":   dport,
		"MaxHops": maxHops,
		"Count":   count,
		"Timeout": timeout,
	})
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	mode := Mode(strings.ToLower(r.URL.Query().Get("mode")))
	if mode != ModeICMP && mode != ModeTCP && mode != ModeUDP {
		mode = ModeICMP
	}
	maxHops := parseInt(r.URL.Query().Get("maxhops"), 1, 64, cfg.MaxHops)
	count := parseInt(r.URL.Query().Get("count"), 1, 10, cfg.Count)
	timeout := parseInt(r.URL.Query().Get("timeout"), 300, 5000, cfg.TimeoutMS)
	dport := uint16(parseInt(r.URL.Query().Get("dport"), 1, 65535, 33434))

	params := TraceParams{
		Target:    target,
		Mode:      mode,
		DPort:     dport,
		MaxHops:   maxHops,
		Count:     count,
		TimeoutMS: timeout,
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	ch := make(chan HopStat, 1)
	go func() {
		defer close(ch)
		if err := doTrace(ctx, params, ch); err != nil {
			emitEvent(w, map[string]any{"type": "error", "msg": err.Error()})
		}
	}()

	emitEvent(w, map[string]any{"type": "start", "target": target, "mode": params.Mode, "dport": params.DPort})
	for hop := range ch {
		emitEvent(w, map[string]any{"type": "hop", "data": hop})
	}
	emitEvent(w, map[string]any{"type": "done"})
}

func emitEvent(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func parseInt(s string, min, max, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// =================== 调度 ===================

func doTrace(ctx context.Context, p TraceParams, out chan<- HopStat) error {
	ipaddr, err := resolveBestIP(ctx, p.Target)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", p.Target, err)
	}

	switch p.Mode {
	case ModeICMP:
		return traceICMP(ctx, ipaddr, p.Count, p.TimeoutMS, p.MaxHops, out)
	case ModeTCP:
		return traceTCP(ctx, ipaddr, p.DPort, p.Count, p.TimeoutMS, p.MaxHops, out)
	case ModeUDP:
		return traceUDP(ctx, ipaddr, p.DPort, p.Count, p.TimeoutMS, p.MaxHops, out)
	default:
		return errors.New("unknown mode")
	}
}

func resolveBestIP(ctx context.Context, host string) (*net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}
	r := &net.Resolver{}
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	// 优先返回 IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return &net.IPAddr{IP: ip}, nil
		}
	}
	return &net.IPAddr{IP: ips[0]}, nil
}

// =================== ICMP traceroute ===================

func traceICMP(ctx context.Context, dst *net.IPAddr, count, timeoutMS, maxHops int, out chan<- HopStat) error {
	is6 := dst.IP.To4() == nil
	var network string
	var proto int
	if is6 {
		network = "ip6:ipv6-icmp"
		proto = 58
	} else {
		network = "ip4:icmp"
		proto = 1
	}

	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return fmt.Errorf("icmp listen: %w", err)
	}
	defer c.Close()

	pid := os.Getpid() & 0xffff

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := HopStat{Hop: ttl, Sent: count}
		results := make([]ProbeResult, 0, count)
		hopIPs := make(map[string]int)

		for i := 0; i < count; i++ {
			seq := ttl*1000 + i

			var msg icmp.Message
			if is6 {
				msg = icmp.Message{
					Type: ipv6.ICMPTypeEchoRequest,
					Code: 0,
					Body: &icmp.Echo{ID: pid, Seq: seq, Data: []byte("QwQTrace")},
				}
			} else {
				msg = icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: &icmp.Echo{ID: pid, Seq: seq, Data: []byte("QwQTrace")},
				}
			}

			b, _ := msg.Marshal(nil)

			// 设置 TTL/HopLimit
			if is6 {
				_ = c.IPv6PacketConn().SetHopLimit(ttl)
			} else {
				_ = c.IPv4PacketConn().SetTTL(ttl)
			}

			start := time.Now()
			if _, err := c.WriteTo(b, dst); err != nil {
				results = append(results, ProbeResult{TTL: ttl, Seq: i, Received: false})
				continue
			}

			// 读取响应
			deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
			received := false

			for time.Now().Before(deadline) && !received {
				_ = c.SetReadDeadline(deadline)
				buf := make([]byte, 1500)
				n, peer, err := c.ReadFrom(buf)
				if err != nil {
					break
				}

				rm, err := icmp.ParseMessage(proto, buf[:n])
				if err != nil {
					continue
				}

				peerIP := stripZone(peer.String())
				rtt := time.Since(start)

				switch rm.Type {
				case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
					if body, ok := rm.Body.(*icmp.Echo); ok && body.ID == pid && body.Seq == seq {
						results = append(results, ProbeResult{TTL: ttl, Seq: i, IP: peerIP, RTT: rtt, Type: "echo-reply", Received: true})
						hopIPs[peerIP]++
						hop.Reachable = true
						received = true
					}

				case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
					if validateICMPResponse(rm, pid, seq) {
						results = append(results, ProbeResult{TTL: ttl, Seq: i, IP: peerIP, RTT: rtt, Type: "ttl-exceeded", Received: true})
						hopIPs[peerIP]++
						received = true
					}

				case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
					if validateICMPResponse(rm, pid, seq) {
						results = append(results, ProbeResult{TTL: ttl, Seq: i, IP: peerIP, RTT: rtt, Type: "destination", Received: true})
						hopIPs[peerIP]++
						received = true
					}
				}
			}

			if !received {
				results = append(results, ProbeResult{TTL: ttl, Seq: i, Received: false})
			}
		}

		processHopResults(&hop, results, hopIPs)

		select {
		case out <- hop:
		case <-ctx.Done():
			return ctx.Err()
		}

		if hop.Reachable && len(hop.IPs) > 0 && normalizeIP(hop.IPs[0]) == normalizeIP(dst.IP.String()) {
			break
		}
	}
	return nil
}

// =================== UDP traceroute (标准实现) ===================

func traceUDP(ctx context.Context, dst *net.IPAddr, basePort uint16, count, timeoutMS, maxHops int, out chan<- HopStat) error {
	is6 := dst.IP.To4() == nil

	var network string
	var proto int
	if is6 {
		network = "ip6:ipv6-icmp"
		proto = 58
	} else {
		network = "ip4:icmp"
		proto = 1
	}

	icmpConn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return fmt.Errorf("icmp listen: %w", err)
	}
	defer icmpConn.Close()

	if basePort == 0 {
		basePort = 33434
	}

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := HopStat{Hop: ttl, Sent: count}
		hopIPs := make(map[string]int)
		var results []ProbeResult

		for i := 0; i < count; i++ {
			// 标准 traceroute: 每次增加端口号
			dport := basePort + uint16((ttl-1)*count+i)

			// 创建 UDP 连接
			conn, err := createUDPSocket(dst.IP.String(), dport, ttl, is6)
			if err != nil {
				results = append(results, ProbeResult{TTL: ttl, Seq: i, Received: false})
				continue
			}

			// 发送数据
			payload := []byte("QwQTrace")
			startTime := time.Now()
			_, err = conn.Write(payload)
			conn.Close()

			if err != nil {
				results = append(results, ProbeResult{TTL: ttl, Seq: i, Received: false})
				continue
			}

			// 等待 ICMP 响应
			deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
			received := false

			for time.Now().Before(deadline) && !received {
				buf := make([]byte, 1500)
				icmpConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, peer, err := icmpConn.ReadFrom(buf)

				if err != nil || n == 0 {
					continue
				}

				rm, err := icmp.ParseMessage(proto, buf[:n])
				if err != nil {
					continue
				}

				// 验证端口匹配
				if extractPort := extractUDPPortFromICMP(rm, is6); extractPort == dport {
					peerIP := stripZone(peer.String())
					rtt := time.Since(startTime)

					result := ProbeResult{
						TTL:      ttl,
						Seq:      i,
						IP:       peerIP,
						RTT:      rtt,
						Received: true,
					}

					switch rm.Type {
					case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
						result.Type = "ttl-exceeded"
					case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
						result.Type = "destination"
						if rm.Code == 3 { // Port Unreachable
							hop.Reachable = true
						}
					}

					results = append(results, result)
					hopIPs[peerIP]++
					received = true
				}
			}

			if !received {
				results = append(results, ProbeResult{TTL: ttl, Seq: i, Received: false})
			}
		}

		processHopResults(&hop, results, hopIPs)

		select {
		case out <- hop:
		case <-ctx.Done():
			return ctx.Err()
		}

		if hop.Reachable {
			break
		}
	}

	return nil
}

// 创建 UDP socket
func createUDPSocket(dst string, port uint16, ttl int, is6 bool) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 100 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if is6 {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
				} else {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				}
			})
		},
	}
	return dialer.Dial("udp", fmt.Sprintf("%s:%d", dst, port))
}

// =================== TCP traceroute ===================

func traceTCP(ctx context.Context, dst *net.IPAddr, basePort uint16, count, timeoutMS, maxHops int, out chan<- HopStat) error {
	is6 := dst.IP.To4() == nil

	var network string
	var proto int
	if is6 {
		network = "ip6:ipv6-icmp"
		proto = 58
	} else {
		network = "ip4:icmp"
		proto = 1
	}

	icmpConn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return fmt.Errorf("icmp listen: %w", err)
	}
	defer icmpConn.Close()

	if basePort == 0 {
		basePort = 80
	}

	// 创建全局ICMP响应收集器
	type icmpResponse struct {
		peer string
		msg  *icmp.Message
		time time.Time
	}

	respChan := make(chan icmpResponse, 100)
	stopCollector := make(chan struct{})

	// 启动ICMP响应收集器
	go func() {
		for {
			select {
			case <-stopCollector:
				return
			default:
				buf := make([]byte, 1500)
				icmpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, peer, err := icmpConn.ReadFrom(buf)
				if err != nil {
					continue
				}

				if n > 0 {
					rm, err := icmp.ParseMessage(proto, buf[:n])
					if err == nil {
						select {
						case respChan <- icmpResponse{
							peer: peer.String(),
							msg:  rm,
							time: time.Now(),
						}:
						case <-stopCollector:
							return
						}
					}
				}
			}
		}
	}()

	defer close(stopCollector)

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := HopStat{Hop: ttl, Sent: count}
		hopIPs := make(map[string]int)

		// 存储每个探测的信息
		type probeInfo struct {
			seq       int
			startTime time.Time
			received  bool
			result    ProbeResult
		}

		probes := make([]*probeInfo, count)

		// 发送所有TCP探测包
		for i := 0; i < count; i++ {
			probe := &probeInfo{
				seq:       i,
				startTime: time.Now(),
				received:  false,
			}
			probes[i] = probe

			// 创建TCP连接（异步）
			go func(idx int, p *probeInfo) {
				dialer := &net.Dialer{
					Timeout: time.Duration(timeoutMS) * time.Millisecond,
					Control: func(network, address string, c syscall.RawConn) error {
						return c.Control(func(fd uintptr) {
							if is6 {
								syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
							} else {
								syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
							}
						})
					},
				}

				conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", dst.IP.String(), basePort))

				if err == nil {
					// TCP连接成功 - 到达目标
					conn.Close()
					rtt := time.Since(p.startTime)
					p.received = true
					p.result = ProbeResult{
						TTL:      ttl,
						Seq:      idx,
						IP:       dst.IP.String(),
						RTT:      rtt,
						Type:     "tcp-reply",
						Received: true,
					}
					hop.Reachable = true
				}
			}(i, probe)

			// 小延迟避免发包过快
			time.Sleep(50 * time.Millisecond)
		}

		// 等待响应（收集ICMP或TCP响应）
		deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)

		for time.Now().Before(deadline) {
			select {
			case resp := <-respChan:
				peerIP := stripZone(resp.peer)

				// 尝试匹配端口（TCP）
				extractedPort := extractTCPPortFromICMP(resp.msg, is6)
				if extractedPort != basePort {
					continue
				}

				// 查找对应的探测（通过时间匹配）
				for idx, probe := range probes {
					if probe.received {
						continue
					}

					// 检查时间范围（响应时间应该在探测之后）
					if resp.time.After(probe.startTime) && resp.time.Sub(probe.startTime) < time.Duration(timeoutMS)*time.Millisecond {
						rtt := resp.time.Sub(probe.startTime)

						respType := "unknown"
						switch resp.msg.Type {
						case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
							respType = "ttl-exceeded"
						case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
							respType = "destination"
						}

						probe.received = true
						probe.result = ProbeResult{
							TTL:      ttl,
							Seq:      idx,
							IP:       peerIP,
							RTT:      rtt,
							Type:     respType,
							Received: true,
						}

						hopIPs[peerIP]++
						break
					}
				}

			case <-time.After(30 * time.Millisecond):
				// 检查是否所有探测都已完成
				allDone := true
				for _, probe := range probes {
					if !probe.received {
						// 检查是否超时
						if time.Since(probe.startTime) < time.Duration(timeoutMS)*time.Millisecond {
							allDone = false
							break
						}
					}
				}
				if allDone {
					goto collectResults
				}
			}
		}

	collectResults:
		// 收集最终结果
		results := make([]ProbeResult, 0, count)
		for _, probe := range probes {
			if !probe.received {
				probe.result = ProbeResult{
					TTL:      ttl,
					Seq:      probe.seq,
					Received: false,
				}
			}
			results = append(results, probe.result)
		}

		// 处理结果
		processHopResults(&hop, results, hopIPs)

		select {
		case out <- hop:
		case <-ctx.Done():
			return ctx.Err()
		}

		// 如果到达目标，停止
		if hop.Reachable {
			break
		}
	}

	return nil
}

// =================== ICMP 响应解析 ===================

// 改进的TCP端口提取函数
func extractTCPPortFromICMP(msg *icmp.Message, is6 bool) uint16 {
	if msg == nil {
		return 0
	}

	var origData []byte

	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		origData = body.Data
	case *icmp.DstUnreach:
		origData = body.Data
	default:
		return 0
	}

	if len(origData) == 0 {
		return 0
	}

	if is6 {
		// IPv6处理
		if len(origData) < 44 {
			return 0
		}

		// 检查Next Header字段
		nextHeader := origData[6]
		offset := 40

		// 处理可能的扩展头部
		for offset < len(origData)-4 {
			switch nextHeader {
			case 6: // TCP协议
				if len(origData) >= offset+4 {
					// TCP目标端口在TCP头部的第2-3字节
					return binary.BigEndian.Uint16(origData[offset+2 : offset+4])
				}
				return 0

			case 0, 43, 44, 60: // 扩展头部
				if len(origData) < offset+8 {
					return 0
				}
				nextHeader = origData[offset]
				extLen := 8 + int(origData[offset+1])*8
				offset += extLen

			default:
				return 0
			}
		}

	} else {
		// IPv4处理
		if len(origData) < 20 {
			return 0
		}

		// IP头部长度
		ipHdrLen := int((origData[0] & 0x0f) * 4)
		if ipHdrLen < 20 || len(origData) < ipHdrLen+4 {
			return 0
		}

		// 检查协议字段（第9字节）- 必须是TCP(6)
		if origData[9] != 6 {
			return 0
		}

		// TCP头部
		if len(origData) < ipHdrLen+4 {
			return 0
		}

		// TCP目标端口（TCP头部的第2-3字节）
		return binary.BigEndian.Uint16(origData[ipHdrLen+2 : ipHdrLen+4])
	}

	return 0
}

func validateICMPResponse(msg *icmp.Message, pid, seq int) bool {
	var origData []byte

	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		origData = body.Data
	case *icmp.DstUnreach:
		origData = body.Data
	default:
		return false
	}

	if len(origData) < 28 {
		return false
	}

	ipHdrLen := int((origData[0] & 0x0f) * 4)
	if len(origData) < ipHdrLen+8 {
		return false
	}

	icmpData := origData[ipHdrLen:]
	if len(icmpData) >= 8 && icmpData[0] == 8 {
		origID := int(binary.BigEndian.Uint16(icmpData[4:6]))
		origSeq := int(binary.BigEndian.Uint16(icmpData[6:8]))
		return origID == pid && origSeq == seq
	}

	return false
}

func extractUDPPortFromICMP(msg *icmp.Message, is6 bool) uint16 {
	var origData []byte

	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		origData = body.Data
	case *icmp.DstUnreach:
		origData = body.Data
	default:
		return 0
	}

	if is6 {
		if len(origData) < 48 {
			return 0
		}
		// 检查 Next Header
		if origData[6] == 17 { // UDP
			return binary.BigEndian.Uint16(origData[42:44])
		}
	} else {
		if len(origData) < 28 {
			return 0
		}
		ipHdrLen := int((origData[0] & 0x0f) * 4)
		if len(origData) < ipHdrLen+4 || origData[9] != 17 {
			return 0
		}
		return binary.BigEndian.Uint16(origData[ipHdrLen+2 : ipHdrLen+4])
	}

	return 0
}

// =================== 结果处理 ===================

func processHopResults(hop *HopStat, results []ProbeResult, hopIPs map[string]int) {
	var rtts []time.Duration
	recv := 0

	for _, result := range results {
		if result.Received {
			recv++
			rtts = append(rtts, result.RTT)
		}
	}

	// 按出现次数排序 IP
	type ipCount struct {
		ip    string
		count int
	}
	var ipList []ipCount
	for ip, cnt := range hopIPs {
		ipList = append(ipList, ipCount{ip: ip, count: cnt})
	}

	// 冒泡排序
	for i := 0; i < len(ipList); i++ {
		for j := i + 1; j < len(ipList); j++ {
			if ipList[j].count > ipList[i].count {
				ipList[i], ipList[j] = ipList[j], ipList[i]
			}
		}
	}

	for _, item := range ipList {
		hop.IPs = append(hop.IPs, item.ip)
		if ip := net.ParseIP(item.ip); ip != nil {
			hop.Hostnames = append(hop.Hostnames, lookupHostname(ip))
			geo, as := geoDB.Lookup(ip)
			hop.Geos = append(hop.Geos, geo)
			hop.ASes = append(hop.ASes, as)
		} else {
			hop.Hostnames = append(hop.Hostnames, "--")
			hop.Geos = append(hop.Geos, "--")
			hop.ASes = append(hop.ASes, "--")
		}
	}

	hop.LossPct = 100 * (1 - float64(recv)/float64(hop.Sent))

	if len(rtts) > 0 {
		hop.LastMS = int(rtts[len(rtts)-1].Milliseconds())
		hop.BestMS = int(minDur(rtts).Milliseconds())
		hop.WorstMS = int(maxDur(rtts).Milliseconds())
		hop.AvgMS = int(meanDur(rtts).Milliseconds())
	}
}

// =================== DNS 反查 ===================

var dnsCache = sync.Map{}

func lookupHostname(ip net.IP) string {
	ipStr := ip.String()

	if cached, ok := dnsCache.Load(ipStr); ok {
		return cached.(string)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)
	if err != nil || len(names) == 0 {
		dnsCache.Store(ipStr, "--")
		return "--"
	}

	hostname := strings.TrimSuffix(names[0], ".")
	dnsCache.Store(ipStr, hostname)
	return hostname
}

// =================== 工具函数 ===================

func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		if j := strings.IndexByte(s[i:], ']'); j >= 0 {
			return s[:i] + s[i+j:]
		}
		return s[:i]
	}
	return s
}

func normalizeIP(s string) string {
	s = strings.Trim(s, "[]")
	if i := strings.LastIndex(s, ":"); i > 0 {
		if strings.Count(s[:i], ".") == 3 {
			s = s[:i]
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func meanDur(a []time.Duration) time.Duration {
	if len(a) == 0 {
		return 0
	}
	var s time.Duration
	for _, v := range a {
		s += v
	}
	return s / time.Duration(len(a))
}

func minDur(a []time.Duration) time.Duration {
	if len(a) == 0 {
		return 0
	}
	m := a[0]
	for _, v := range a {
		if v < m {
			m = v
		}
	}
	return m
}

func maxDur(a []time.Duration) time.Duration {
	if len(a) == 0 {
		return 0
	}
	m := a[0]
	for _, v := range a {
		if v > m {
			m = v
		}
	}
	return m
}
