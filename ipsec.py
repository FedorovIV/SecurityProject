from scapy.all import sniff, UDP, Raw, IP, ESP
from scapy.all import conf

from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple

class IPSecDetector:
    def __init__(self):
        self.setup_logging()
        self.connections: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        self.suspected_ipsec = set()
        self.packet_timestamps = defaultdict(list)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """Анализ отдельного пакета"""
        if IP in packet:
            if packet[IP].proto == 50:  # ESP protocol number is 50
                src = packet[IP].src
                dst = packet[IP].dst
                self.logger.info(f"Detected IPSec ESP packet: {src} -> {dst}")
                return True
            
            if UDP in packet and Raw in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_size = len(packet[Raw])
                connection = (packet[IP].src, packet[IP].dst)
                
                # Проверяем стандартные порты IPSec
                if src_port in {500, 4500} or dst_port in {500, 4500}:
                    self.logger.info(f"Detected IPSec default port usage: {src_port} -> {dst_port}")
                    return True
                
                # Сохраняем размер пакета и время
                self.connections[connection].append(payload_size)
                self.packet_timestamps[connection].append(time.time())
                
                # Проверяем характерные размеры пакетов
                if self.check_packet_patterns(connection):
                    return True
        
        return False
    
    def check_packet_patterns(self, connection: Tuple[str, str]) -> bool:
        """Проверка паттернов пакетов"""
        packets = self.connections[connection]
        timestamps = self.packet_timestamps[connection]
        
        if len(packets) < 3:
            return False
            
        # Проверяем характерные размеры handshake для IPSec
        if 148 in packets or 256 in packets:
            self.logger.info(f"Detected IPSec handshake pattern for {connection}")
            return True
            
        # Проверяем периодичность пакетов (для keepalive или контрольных сообщений)
        if len(timestamps) >= 2:
            intervals = [timestamps[i+1] - timestamps[i] 
                        for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            # Проверяем keepalive интервалы (30 ± 10 секунд)
            if 20 <= avg_interval <= 40:
                self.logger.info(f"Detected IPSec keepalive pattern for {connection}")
                return True
                
        # Проверяем размеры пакетов кратные 8 (характерно для IPSec)
        recent_packets = packets[-10:]  # Последние 10 пакетов
        if all(size % 8 == 0 for size in recent_packets):
            self.logger.info(f"Detected IPSec packet size pattern for {connection}")
            return True
            
        return False

    def start_detection(self, interface=None, timeout=60):
        """Запуск обнаружения IPSec"""
        self.logger.info(f"Starting IPSec detection on interface: {interface or 'default'}")
        
        try:
            # Начинаем захват пакетов
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
        print("\nDetection Results:")
        print("-" * 50)
        
        if not self.connections:
            print("No IP connections analyzed")
            return
            
        for connection, packets in self.connections.items():
            src, dst = connection
            print(f"\nConnection: {src} -> {dst}")
            print(f"Total packets: {len(packets)}")
            print(f"Unique packet sizes: {sorted(set(packets))}")
            
            if connection in self.suspected_ipsec:
                print("STATUS: Likely IPSec traffic")
                print("Detected patterns:")
                print("- Characteristic packet sizes")
                print("- Regular timing intervals")
            else:
                print("STATUS: No clear IPSec indicators")

def main():
    detector = IPSecDetector()
    
    print("Starting IPSec Traffic Detection")
    print("This tool will analyze network traffic for IPSec characteristics")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

# Настройка конфигурации на уровень 3 (L3)
# conf.L3socket = conf.L3RawSocket

if __name__ == "__main__":
    main()
    