from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP
from collections import defaultdict, Counter
import time
import logging
import statistics
from queue import Queue

class VPNDetector:
    def __init__(self):
        self.setup_logging()
        self.connections = defaultdict(lambda: {
            'packets': [],
            'protocols': defaultdict(int),
            'last_update': time.time(),
            'detected_vpn_types': set(),
            'confidence_scores': defaultdict(float)
        })
        
        # Определение характерных портов
        self.vpn_ports = {
            'IKEv2': {500, 4500},  # IKEv2/IPsec
            'L2TP': {1701},        # L2TP
            'SSTP': {443},         # SSTP
            'IPsec': {500, 4500}   # IPsec
        }
        
        # Характерные размеры пакетов для разных протоколов
        self.packet_sizes = {
            'IKEv2': [148, 256, 384],  # Характерные размеры IKEv2
            'L2TP': [52, 60, 96],      # L2TP контрольные пакеты
            'SSTP': [110, 184, 214],   # SSTP handshake
            'IPsec': [62, 90, 94]      # IPsec
        }

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """Анализ пакета на признаки VPN"""
        try:
            if IP not in packet:
                return False

            connection_id = self.get_connection_id(packet)
            if not connection_id:
                return False

            conn_data = self.connections[connection_id]
            conn_data['last_update'] = time.time()

            # Сохраняем базовую информацию о пакете
            packet_info = {
                'time': time.time(),
                'size': len(packet),
                'protocol': packet[IP].proto,
                'src_port': self.get_port(packet, 'src'),
                'dst_port': self.get_port(packet, 'dst'),
                'flags': self.get_flags(packet)
            }
            conn_data['packets'].append(packet_info)

            # Анализируем пакет на признаки разных VPN протоколов
            self.detect_ikev2(packet, conn_data)
            self.detect_l2tp(packet, conn_data)
            self.detect_sstp(packet, conn_data)
            self.detect_ipsec(packet, conn_data)

            # Обновляем общую уверенность в обнаружении
            return self.update_detection_confidence(conn_data)

        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return False

    def get_connection_id(self, packet):
        """Получение идентификатора соединения"""
        try:
            if IP in packet:
                if TCP in packet:
                    return (
                        f"{packet[IP].src}:{packet[TCP].sport}",
                        f"{packet[IP].dst}:{packet[TCP].dport}",
                        'TCP'
                    )
                elif UDP in packet:
                    return (
                        f"{packet[IP].src}:{packet[UDP].sport}",
                        f"{packet[IP].dst}:{packet[UDP].dport}",
                        'UDP'
                    )
                else:
                    return (
                        packet[IP].src,
                        packet[IP].dst,
                        'IP'
                    )
            return None
        except Exception:
            return None

    def get_port(self, packet, direction):
        """Получение порта из пакета"""
        try:
            if TCP in packet:
                return packet[TCP].sport if direction == 'src' else packet[TCP].dport
            elif UDP in packet:
                return packet[UDP].sport if direction == 'src' else packet[UDP].dport
            return None
        except Exception:
            return None

    def get_flags(self, packet):
        """Получение флагов из пакета"""
        try:
            if TCP in packet:
                return packet[TCP].flags
            return None
        except Exception:
            return None

    def detect_ikev2(self, packet, conn_data):
        """Обнаружение IKEv2"""
        if UDP in packet and Raw in packet:
            udp_payload = packet[Raw].load
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Проверяем порты IKEv2
            if src_port in self.vpn_ports['IKEv2'] or dst_port in self.vpn_ports['IKEv2']:
                # Проверяем характерные размеры пакетов
                if len(packet) in self.packet_sizes['IKEv2']:
                    conn_data['confidence_scores']['IKEv2'] += 0.3

                # Проверяем заголовок IKEv2
                if len(udp_payload) > 4:
                    # IKEv2 имеет характерную структуру заголовка
                    if udp_payload[0] == 0x20:  # Версия IKEv2
                        conn_data['confidence_scores']['IKEv2'] += 0.4
                        conn_data['detected_vpn_types'].add('IKEv2')

    def detect_l2tp(self, packet, conn_data):
        """Обнаружение L2TP"""
        if UDP in packet and Raw in packet:
            udp_payload = packet[Raw].load
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Проверяем порт L2TP
            if src_port == 1701 or dst_port == 1701:
                # Проверяем характерные размеры
                if len(packet) in self.packet_sizes['L2TP']:
                    conn_data['confidence_scores']['L2TP'] += 0.3

                # Проверяем заголовок L2TP
                if len(udp_payload) > 2:
                    # L2TP имеет характерные флаги в заголовке
                    flags = udp_payload[0] & 0xF0
                    if flags in {0x80, 0xC0}:  # Типичные флаги L2TP
                        conn_data['confidence_scores']['L2TP'] += 0.4
                        conn_data['detected_vpn_types'].add('L2TP')

    def detect_sstp(self, packet, conn_data):
        """Обнаружение SSTP"""
        if TCP in packet and Raw in packet:
            tcp_payload = packet[Raw].load
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # SSTP работает через HTTPS (порт 443)
            if src_port == 443 or dst_port == 443:
                # Проверяем характерные размеры SSTP пакетов
                if len(packet) in self.packet_sizes['SSTP']:
                    conn_data['confidence_scores']['SSTP'] += 0.3

                # Проверяем заголовок SSTP
                if len(tcp_payload) > 4:
                    # SSTP имеет характерную структуру HTTP
                    if b'SSTP_DUPLEX' in tcp_payload or b'X-SSTP-VERSION' in tcp_payload:
                        conn_data['confidence_scores']['SSTP'] += 0.5
                        conn_data['detected_vpn_types'].add('SSTP')

    def detect_ipsec(self, packet, conn_data):
        """Обнаружение IPsec"""
        if IP in packet:
            # Проверяем протокол ESP (50) или AH (51)
            if packet[IP].proto in {50, 51}:
                conn_data['confidence_scores']['IPsec'] += 0.5
                conn_data['detected_vpn_types'].add('IPsec')
            
            # Проверяем NAT-Traversal через UDP
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if src_port in self.vpn_ports['IPsec'] or dst_port in self.vpn_ports['IPsec']:
                    if len(packet) in self.packet_sizes['IPsec']:
                        conn_data['confidence_scores']['IPsec'] += 0.3

    def update_detection_confidence(self, conn_data):
        """Обновление уверенности в обнаружении"""
        # Проверяем накопленные данные
        packets_count = len(conn_data['packets'])
        if packets_count < 5:
            return False

        # Для каждого протокола проверяем уровень уверенности
        for vpn_type, score in conn_data['confidence_scores'].items():
            if score > 0.7:  # Порог уверенности
                return True

        return False

    def start_detection(self, interface=None, timeout=60):
        """Запуск обнаружения"""
        self.logger.info(f"Starting VPN detection on interface: {interface or 'default'}")
        
        try:
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                timeout=timeout,
                store=0
            )
        except KeyboardInterrupt:
            self.logger.info("Detection stopped by user")
        finally:
            self.print_results()

    def print_results(self):
        """Вывод результатов анализа"""
        print("\nVPN Detection Results:")
        print("-" * 60)
        
        if not self.connections:
            print("No connections analyzed")
            return
            
        for connection_id, conn_data in self.connections.items():
            src, dst, proto = connection_id
            print(f"\nConnection: {src} -> {dst} ({proto})")
            print(f"Total packets analyzed: {len(conn_data['packets'])}")
            
            if conn_data['detected_vpn_types']:
                print("\nDetected VPN protocols:")
                for vpn_type in conn_data['detected_vpn_types']:
                    confidence = conn_data['confidence_scores'][vpn_type]
                    print(f"- {vpn_type}: {confidence:.2%} confidence")
            
            # Статистика пакетов
            if conn_data['packets']:
                sizes = [p['size'] for p in conn_data['packets']]
                print(f"\nPacket statistics:")
                print(f"- Average size: {statistics.mean(sizes):.1f} bytes")
                print(f"- Min size: {min(sizes)} bytes")
                print(f"- Max size: {max(sizes)} bytes")

def main():
    detector = VPNDetector()
    
    print("Starting VPN Protocol Detection")
    print("Supported protocols: IKEv2, SSTP, L2TP/IPsec")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

if __name__ == "__main__":
    main()