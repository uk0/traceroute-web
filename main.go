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
	Count:          5,
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
	Type     string // "ttl-exceeded", "destination", "echo-reply", "tcp-reply"
	Received bool
}

// =================== Probe Manager ===================

type ProbeManager struct {
	probes map[string]*ProbeInfo // key: "ttl:seq" or port for TCP/UDP
	mu     sync.RWMutex
}

type ProbeInfo struct {
	TTL       int
	Seq       int
	Port      uint16
	StartTime time.Time
}

func NewProbeManager() *ProbeManager {
	return &ProbeManager{
		probes: make(map[string]*ProbeInfo),
	}
}

func (pm *ProbeManager) Register(ttl, seq int, port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := fmt.Sprintf("%d:%d", ttl, seq)
	if port > 0 {
		key = fmt.Sprintf("port:%d", port)
	}
	pm.probes[key] = &ProbeInfo{
		TTL:       ttl,
		Seq:       seq,
		Port:      port,
		StartTime: time.Now(),
	}
}

func (pm *ProbeManager) Match(ttl, seq int, port uint16) (*ProbeInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	key := fmt.Sprintf("%d:%d", ttl, seq)
	if port > 0 {
		key = fmt.Sprintf("port:%d", port)
	}
	info, ok := pm.probes[key]
	return info, ok
}

func (pm *ProbeManager) Clean(before time.Time) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for k, v := range pm.probes {
		if v.StartTime.Before(before) {
			delete(pm.probes, k)
		}
	}
}

func isRoot() bool {
	return os.Geteuid() == 0
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
	//is6 := ipaddr.IP.To4() == nil

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
	pm := NewProbeManager()

	// 定期清理过期探测记录
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pm.Clean(time.Now().Add(-10 * time.Second))
			}
		}
	}()

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
			pm.Register(ttl, seq, 0)

			var msg icmp.Message
			if is6 {
				msg = icmp.Message{
					Type: ipv6.ICMPTypeEchoRequest,
					Code: 0,
					Body: &icmp.Echo{
						ID:   pid,
						Seq:  seq,
						Data: []byte("QwQTrace"),
					},
				}
			} else {
				msg = icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: &icmp.Echo{
						ID:   pid,
						Seq:  seq,
						Data: []byte("QwQTrace"),
					},
				}
			}

			b, _ := msg.Marshal(nil)

			// 设置 TTL/HopLimit
			if is6 {
				p := c.IPv6PacketConn()
				_ = p.SetHopLimit(ttl)
			} else {
				p := c.IPv4PacketConn()
				_ = p.SetTTL(ttl)
			}

			start := time.Now()
			if _, err := c.WriteTo(b, dst); err != nil {
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
					if body, ok := rm.Body.(*icmp.Echo); ok {
						if body.ID == pid && body.Seq == seq {
							results = append(results, ProbeResult{
								TTL:      ttl,
								Seq:      seq,
								IP:       peerIP,
								RTT:      rtt,
								Type:     "echo-reply",
								Received: true,
							})
							hopIPs[peerIP]++
							hop.Reachable = true
							received = true
						}
					}

				case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
					// 解析原始包来验证是否是我们的探测
					if validateICMPResponse(rm, pid, seq) {
						results = append(results, ProbeResult{
							TTL:      ttl,
							Seq:      seq,
							IP:       peerIP,
							RTT:      rtt,
							Type:     "ttl-exceeded",
							Received: true,
						})
						hopIPs[peerIP]++
						received = true
					}

				case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
					if validateICMPResponse(rm, pid, seq) {
						results = append(results, ProbeResult{
							TTL:      ttl,
							Seq:      seq,
							IP:       peerIP,
							RTT:      rtt,
							Type:     "destination",
							Received: true,
						})
						hopIPs[peerIP]++
						received = true
					}
				}
			}

			if !received {
				results = append(results, ProbeResult{
					TTL:      ttl,
					Seq:      seq,
					Received: false,
				})
			}
		}

		// 处理结果
		processHopResults(&hop, results, hopIPs)

		select {
		case out <- hop:
		case <-ctx.Done():
			return ctx.Err()
		}

		if hop.Reachable && len(hop.IPs) > 0 && sameHost(hop.IPs[0], dst.String()) {
			break
		}
	}
	return nil
}

// =================== UDP traceroute ===================

var udpPortCounter uint32 = 33434

// =================== UDP traceroute (完全修复版) ===================
func traceUDP(ctx context.Context, dst *net.IPAddr, basePort uint16, count, timeoutMS, maxHops int, out chan<- HopStat) error {
	is6 := dst.IP.To4() == nil

	// 监听 ICMP 响应
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

	// 使用基础端口
	if basePort == 0 {
		basePort = 33434
	}

	dstIPStr := dst.IP.String()

	// 用于记录最后一个有效响应的跳数
	lastValidHop := 0
	consecutiveTimeouts := 0

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := HopStat{Hop: ttl, Sent: count}
		hopIPs := make(map[string]int)
		results := make([]ProbeResult, count)
		receivedAny := false

		for i := 0; i < count; i++ {
			// 使用唯一端口
			dport := basePort + uint16((ttl-1)*100+i)
			if dport > 64000 {
				dport = basePort + uint16(ttl*10+i)
			}

			// 发送UDP探测
			conn, err := net.DialTimeout("udp",
				fmt.Sprintf("%s:%d", dst.IP.String(), dport),
				50*time.Millisecond)

			if err == nil {
				// 设置TTL
				if udpConn, ok := conn.(*net.UDPConn); ok {
					raw, _ := udpConn.SyscallConn()
					raw.Control(func(fd uintptr) {
						if is6 {
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
						} else {
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
						}
					})
				}

				// 发送数据
				payload := make([]byte, 32)
				copy(payload, "TRACE")
				binary.BigEndian.PutUint16(payload[5:7], uint16(ttl))
				binary.BigEndian.PutUint16(payload[7:9], uint16(i))
				binary.BigEndian.PutUint16(payload[9:11], dport)

				startTime := time.Now()
				conn.Write(payload)
				conn.Close()

				// 等待ICMP响应
				received := false
				deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)

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

					// 检查端口匹配
					extractedPort := extractUDPPortBetter(rm, is6)
					if extractedPort != dport {
						continue
					}

					peerIP := stripZone(peer.String())
					rtt := time.Since(startTime)

					respType := "unknown"
					switch rm.Type {
					case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
						respType = "ttl-exceeded"

					case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
						respType = "destination"
						// 检查是否是Port Unreachable (code=3)
						if rm.Code == 3 {
							hop.Reachable = true
						}
					}

					results[i] = ProbeResult{
						TTL:      ttl,
						Seq:      i,
						IP:       peerIP,
						RTT:      rtt,
						Type:     respType,
						Received: true,
					}

					hopIPs[peerIP]++
					received = true
					receivedAny = true

					// 检查是否到达目标
					if respType == "destination" || peerIP == dstIPStr {
						hop.Reachable = true
					}
				}

				if !received {
					results[i] = ProbeResult{
						TTL:      ttl,
						Seq:      i,
						Received: false,
					}
				}
			} else {
				results[i] = ProbeResult{
					TTL:      ttl,
					Seq:      i,
					Received: false,
				}
			}

			// 小延迟
			time.Sleep(10 * time.Millisecond)
		}

		// 处理结果
		processHopResults(&hop, results, hopIPs)

		// 记录统计
		if receivedAny {
			lastValidHop = ttl
			consecutiveTimeouts = 0
		} else {
			consecutiveTimeouts++
		}

		select {
		case out <- hop:
		case <-ctx.Done():
			return ctx.Err()
		}

		// 智能终止条件
		if hop.Reachable {
			// 如果标记为可达，直接结束
			break
		}

		// 检查是否已经到达目标附近
		// 如果上一跳(如hop 14)有响应，但当前跳没有响应，可能目标就在这里
		if ttl > 10 && consecutiveTimeouts >= 2 && lastValidHop > 0 {
			// 如果连续2跳都超时，且之前有有效响应，尝试直接探测目标
			if ttl == lastValidHop+2 {
				// 发送一个高TTL的探测直接到目标
				if finalHop := probeDirectTarget(ctx, dst, basePort+9999, 64, timeoutMS, icmpConn, proto); finalHop != nil {
					// 如果收到目标响应，输出最后一跳
					*finalHop = HopStat{
						Hop:       ttl + 1,
						Sent:      1,
						IPs:       []string{dst.IP.String()},
						Hostnames: []string{lookupHostname(dst.IP)},
						LossPct:   0,
						Reachable: true,
					}
					geo, as := geoDB.Lookup(dst.IP)
					finalHop.Geos = []string{geo}
					finalHop.ASes = []string{as}

					select {
					case out <- *finalHop:
					case <-ctx.Done():
					}
					break
				}
			}

			// 如果连续3跳都超时，认为到达了过滤ICMP的目标
			if consecutiveTimeouts >= 3 {
				// 添加最终目标作为最后一跳（推测）
				finalHop := HopStat{
					Hop:       lastValidHop + 1,
					Sent:      1,
					IPs:       []string{dst.IP.String()},
					Hostnames: []string{lookupHostname(dst.IP)},
					LossPct:   0,
					Reachable: true,
				}
				geo, as := geoDB.Lookup(dst.IP)
				finalHop.Geos = []string{geo}
				finalHop.ASes = []string{as}

				select {
				case out <- finalHop:
				case <-ctx.Done():
				}
				break
			}
		}
	}

	return nil
}

// 直接探测目标
func probeDirectTarget(ctx context.Context, dst *net.IPAddr, port uint16, ttl, timeoutMS int, icmpConn *icmp.PacketConn, proto int) *HopStat {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", dst.IP.String(), port), 50*time.Millisecond)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// 设置高TTL
	if udpConn, ok := conn.(*net.UDPConn); ok {
		raw, _ := udpConn.SyscallConn()
		raw.Control(func(fd uintptr) {
			is6 := dst.IP.To4() == nil
			if is6 {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
			} else {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			}
		})
	}

	startTime := time.Now()
	conn.Write([]byte("FINAL_PROBE"))

	deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	for time.Now().Before(deadline) {
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

		// 检查是否收到Port Unreachable响应
		if rm.Type == ipv4.ICMPTypeDestinationUnreachable || rm.Type == ipv6.ICMPTypeDestinationUnreachable {
			if rm.Code == 3 { // Port Unreachable
				// 验证响应来自目标或目标附近
				_ = peer // 使用peer变量
				rtt := time.Since(startTime)
				return &HopStat{
					LastMS: int(rtt.Milliseconds()),
					BestMS: int(rtt.Milliseconds()),
					AvgMS:  int(rtt.Milliseconds()),
				}
			}
		}
	}

	return nil
}

// 改进的端口提取函数
func extractUDPPortBetter(msg *icmp.Message, is6 bool) uint16 {
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
		if len(origData) < 48 {
			return 0
		}
		// 直接跳到UDP头部（假设没有扩展头部）
		return binary.BigEndian.Uint16(origData[42:44])
	} else {
		if len(origData) < 28 {
			return 0
		}
		ipHdrLen := int((origData[0] & 0x0f) * 4)
		if len(origData) < ipHdrLen+4 {
			return 0
		}
		// 确认是UDP协议
		if origData[9] == 17 {
			return binary.BigEndian.Uint16(origData[ipHdrLen+2 : ipHdrLen+4])
		}
	}

	return 0
}

// =================== TCP traceroute ===================

func traceTCP(ctx context.Context, dst *net.IPAddr, basePort uint16, count, timeoutMS, maxHops int, out chan<- HopStat) error {
	is6 := dst.IP.To4() == nil

	// 监听 ICMP 响应
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

	pm := NewProbeManager()

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := HopStat{Hop: ttl, Sent: count}
		results := make([]ProbeResult, 0, count)
		hopIPs := make(map[string]int)

		var wg sync.WaitGroup
		var mu sync.Mutex
		resultsCh := make(chan ProbeResult, count)

		for i := 0; i < count; i++ {
			wg.Add(1)
			go func(seq int) {
				defer wg.Done()

				// 使用固定端口或动态端口
				dport := basePort
				if basePort == 0 {
					dport = 80 // 默认使用80端口
				}

				pm.Register(ttl, seq, dport)

				dialer := &net.Dialer{
					Timeout: time.Duration(timeoutMS) * time.Millisecond,
					Control: func(network, address string, c syscall.RawConn) error {
						var ctrlErr error
						err := c.Control(func(fd uintptr) {
							if is6 {
								ctrlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
							} else {
								ctrlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
							}
						})
						if err != nil {
							return err
						}
						return ctrlErr
					},
				}

				start := time.Now()
				conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", dst.IP.String(), dport))

				if err == nil {
					// TCP连接成功，说明到达目标
					conn.Close()
					rtt := time.Since(start)
					resultsCh <- ProbeResult{
						TTL:      ttl,
						Seq:      seq,
						IP:       dst.IP.String(),
						RTT:      rtt,
						Type:     "tcp-reply",
						Received: true,
					}
					mu.Lock()
					hop.Reachable = true
					mu.Unlock()
					return
				}

				// 读取 ICMP 响应
				deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
				for time.Now().Before(deadline) {
					_ = icmpConn.SetReadDeadline(deadline)
					buf := make([]byte, 1500)
					n, peer, err := icmpConn.ReadFrom(buf)

					if err != nil {
						continue
					}

					rm, err := icmp.ParseMessage(proto, buf[:n])
					if err != nil {
						continue
					}

					peerIP := stripZone(peer.String())

					// 验证是否是我们的探测包的响应
					if matchedPort := extractTCPPort(rm, is6); matchedPort == dport {
						rtt := time.Since(start)

						respType := "unknown"
						switch rm.Type {
						case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
							respType = "ttl-exceeded"
						case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
							respType = "destination"
						}

						resultsCh <- ProbeResult{
							TTL:      ttl,
							Seq:      seq,
							IP:       peerIP,
							RTT:      rtt,
							Type:     respType,
							Received: true,
						}
						return
					}
				}

				resultsCh <- ProbeResult{TTL: ttl, Seq: seq, Received: false}
			}(i)
		}

		// 收集结果
		go func() {
			wg.Wait()
			close(resultsCh)
		}()

		for result := range resultsCh {
			mu.Lock()
			results = append(results, result)
			if result.Received && result.IP != "" {
				hopIPs[result.IP]++
			}
			mu.Unlock()
		}

		// 处理结果
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

// =================== ICMP 响应解析 ===================

func validateICMPResponse(msg *icmp.Message, pid, seq int) bool {
	// Time Exceeded 和 Destination Unreachable 消息包含原始IP包
	var origData []byte

	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		origData = body.Data
	case *icmp.DstUnreach:
		origData = body.Data
	default:
		return false
	}

	if len(origData) < 28 { // IP header (20) + ICMP header (8)
		return false
	}

	// 跳过IP头部（通常是20字节，但可能有选项）
	ipHdrLen := int((origData[0] & 0x0f) * 4)
	if len(origData) < ipHdrLen+8 {
		return false
	}

	// 解析ICMP头部
	icmpData := origData[ipHdrLen:]
	if len(icmpData) >= 8 {
		// 检查ICMP类型是否为Echo Request
		if icmpData[0] == 8 { // Echo Request
			// 提取ID和Seq
			origID := int(binary.BigEndian.Uint16(icmpData[4:6]))
			origSeq := int(binary.BigEndian.Uint16(icmpData[6:8]))
			return origID == pid && origSeq == seq
		}
	}

	return false
}

func extractUDPPort(msg *icmp.Message, is6 bool) uint16 {
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
		// IPv6: 跳过IPv6头部（40字节）
		if len(origData) < 40+8 {
			return 0
		}
		// UDP头部从第40字节开始
		udpData := origData[40:]
		if len(udpData) >= 4 {
			return binary.BigEndian.Uint16(udpData[2:4]) // 目标端口
		}
	} else {
		// IPv4: 跳过IP头部
		if len(origData) < 20+8 {
			return 0
		}
		ipHdrLen := int((origData[0] & 0x0f) * 4)
		if len(origData) < ipHdrLen+8 {
			return 0
		}
		// UDP头部
		udpData := origData[ipHdrLen:]
		if len(udpData) >= 4 {
			return binary.BigEndian.Uint16(udpData[2:4]) // 目标端口
		}
	}

	return 0
}

func extractTCPPort(msg *icmp.Message, is6 bool) uint16 {
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
		// IPv6: 跳过IPv6头部（40字节）
		if len(origData) < 40+8 {
			return 0
		}
		// TCP头部从第40字节开始
		tcpData := origData[40:]
		if len(tcpData) >= 4 {
			return binary.BigEndian.Uint16(tcpData[2:4]) // 目标端口
		}
	} else {
		// IPv4: 跳过IP头部
		if len(origData) < 20+8 {
			return 0
		}
		ipHdrLen := int((origData[0] & 0x0f) * 4)
		if len(origData) < ipHdrLen+8 {
			return 0
		}
		// TCP头部
		tcpData := origData[ipHdrLen:]
		if len(tcpData) >= 4 {
			return binary.BigEndian.Uint16(tcpData[2:4]) // 目标端口
		}
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

	// 收集所有响应的 IP（按出现次数排序）
	type ipCount struct {
		ip    string
		count int
	}
	var ipList []ipCount
	for ip, cnt := range hopIPs {
		ipList = append(ipList, ipCount{ip: ip, count: cnt})
	}
	// 按出现次数降序排序
	for i := 0; i < len(ipList); i++ {
		for j := i + 1; j < len(ipList); j++ {
			if ipList[j].count > ipList[i].count {
				ipList[i], ipList[j] = ipList[j], ipList[i]
			}
		}
	}

	// 记录所有 IP 和对应信息
	for _, item := range ipList {
		hop.IPs = append(hop.IPs, item.ip)
		if ip := parseHostIP(item.ip); ip != nil {
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

	// 检查缓存
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

	// 去掉末尾的点
	hostname := strings.TrimSuffix(names[0], ".")
	dnsCache.Store(ipStr, hostname)
	return hostname
}

// =================== 杂项工具 ===================

func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		j := strings.IndexByte(s[i:], ']')
		if j >= 0 {
			return s[:i] + s[i+j:]
		}
		return s[:i]
	}
	return s
}

func sameHost(a, b string) bool {
	aa := strings.Trim(a, "[]")
	bb := strings.Trim(b, "[]")
	if i := strings.LastIndexByte(aa, ':'); i > -1 && strings.Count(aa, ":") == 1 {
		aa = aa[:i]
	}
	if i := strings.LastIndexByte(bb, ':'); i > -1 && strings.Count(bb, ":") == 1 {
		bb = bb[:i]
	}
	return aa == bb
}

func parseHostIP(s string) net.IP {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if i := strings.LastIndexByte(s, ':'); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	return net.ParseIP(s)
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
