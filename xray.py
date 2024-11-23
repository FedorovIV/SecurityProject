from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple
import ssl
import socket


class ProtocolDetector:
    def __init__(self):
        self.setup_logging()
        self.connections: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        self.suspected_connections = set()
        self.packet_timestamps = defaultdict(list)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """Анализ сетевого пакета"""
        if TCP in packet:
            src = packet[TCP].sport
            dst = packet[TCP].dport
            proto = "TCP"
            
            # Анализируем порты по умолчанию для HTTPS
            if src == 443 or dst == 443:
                self.logger.info(f"Detected HTTPS port usage: {src} -> {dst}")
                pass
                
            # Анализируем содержимое пакета
            if Raw in packet:
                payload = packet[Raw].load
                payload_size = len(payload)
                connection = (packet.src, packet.dst, proto)
                
                packet_info = {
                    'size': payload_size,
                    'time': time.time(),
                    'payload': payload
                }
                
                self.connections[connection].append(packet_info)
                self.packet_timestamps[connection].append(time.time())
                
                if self.check_traffic_patterns(connection):
                    self.suspected_connections.add(connection)
                    return True
                    
        return False
    
    def check_traffic_patterns(self, connection: Tuple[str, str, str]) -> bool:
        """Проверка характерных паттернов трафика"""
        packets = self.connections[connection]
        
        if len(packets) < 5:
            return False
            
        # Анализ размеров пакетов
        packet_sizes = [p['size'] for p in packets]
        
        # Проверка TLS характеристик
        has_tls = self.check_tls_patterns(packets)
        
        # Анализ временных интервалов
        if len(self.packet_timestamps[connection]) >= 2:
            intervals = [self.packet_timestamps[connection][i+1] - self.packet_timestamps[connection][i] 
                        for i in range(len(self.packet_timestamps[connection])-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            # Проверка регулярности соединения
            has_regular_timing = self.check_timing_patterns(intervals)
            
            if has_tls and has_regular_timing:
                return True
            
        return False
        
    def check_tls_patterns(self, packets: List[dict]) -> bool:
        """Анализ TLS характеристик"""
        for packet in packets:
            payload = packet['payload']
            if len(payload) > 5:
                # Проверяем базовые характеристики TLS
                if (payload[0] == 0x16 or  # Handshake
                    payload[0] == 0x17):   # Application Data
                    return True
        return False
        
    def check_timing_patterns(self, intervals: List[float]) -> bool:
        """Анализ временных паттернов"""
        if not intervals:
            return False
            
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        
        # Проверка регулярности интервалов
        return variance < 1.0  # Порог может быть настроен
        
    def analyze_tls_certificates(self, host: str, port: int = 443) -> dict:
        """Анализ TLS сертификатов"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            self.logger.error(f"Certificate analysis error: {e}")
            return {}

    def start_detection(self, interface=None, timeout=60):
        """Запуск анализа трафика"""
        self.logger.info(f"Starting traffic analysis on interface: {interface or 'default'}")
        
        try:
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                timeout=timeout,
                store=0
            )
        except KeyboardInterrupt:
            self.logger.info("Analysis stopped by user")
        finally:
            self.print_results()
    
    def print_results(self):
        """Вывод результатов анализа"""
        print("\nTraffic Analysis Results:")
        print("-" * 50)
        
        if not self.connections:
            print("No relevant connections analyzed")
            return
            
        for connection, packets in self.connections.items():
            src, dst, proto = connection
            print(f"\nConnection: {src} -> {dst} ({proto})")
            print(f"Total packets: {len(packets)}")
            print(f"Unique packet sizes: {sorted(set(p['size'] for p in packets))}")
            
            if connection in self.suspected_connections:
                print("STATUS: Detected characteristic patterns")
                print("Patterns found:")
                print("- TLS traffic characteristics")
                print("- Regular timing patterns")
                print("- Specific packet size distributions")
            else:
                print("STATUS: No specific indicators")

def main():
    detector = ProtocolDetector()
    
    print("Starting Network Traffic Analysis")
    print("This tool will analyze network traffic patterns")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

if __name__ == "__main__":
    main()
