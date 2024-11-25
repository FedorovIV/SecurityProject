from scapy.all import sniff, UDP, Raw
from scapy.all import conf

from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple

class WireGuardDetector:
    def __init__(self):
        self.setup_logging()
        self.connections: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        self.suspected_wireguard = set()
        self.packet_timestamps = defaultdict(list)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        
        """Анализ отдельного пакета"""
        if UDP in packet:
            src = packet[UDP].sport
            dst = packet[UDP].dport
            # print(packet[UDP].payload)

            # Проверяем стандартный порт
            if src == 51820 or dst == 51820:
                self.logger.info(f"Detected WireGuard default port usage: {src} -> {dst}")
                return True
            
            # Анализируем размер пакета
            if Raw in packet:
                payload_size = len(packet[Raw])
                connection = (packet.src, packet.dst)
                
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
            
        # Проверяем характерные размеры handshake
        if 148 in packets and 92 in packets:
            self.logger.info(f"Detected WireGuard handshake pattern for {connection}")
            return True
            
        # Проверяем периодичность пакетов
        if len(timestamps) >= 2:
            intervals = [timestamps[i+1] - timestamps[i] 
                        for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            # Проверяем keepalive интервалы (15 ± 5 секунд)
            if 10 <= avg_interval <= 20:
                self.logger.info(f"Detected WireGuard keepalive pattern for {connection}")
                return True
                
        # Проверяем размеры пакетов кратные 16
        recent_packets = packets[-10:]  # Последние 10 пакетов
        if all(size % 16 == 0 for size in recent_packets):
            self.logger.info(f"Detected WireGuard packet size pattern for {connection}")
            return True
            
        return False

    def start_detection(self, interface=None, timeout=60):
        """Запуск обнаружения WireGuard"""
        self.logger.info(f"Starting WireGuard detection on interface: {interface or 'default'}")
        
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
            print("No UDP connections analyzed")
            return
            
        for connection, packets in self.connections.items():
            src, dst = connection
            print(f"\nConnection: {src} -> {dst}")
            print(f"Total packets: {len(packets)}")
            print(f"Unique packet sizes: {sorted(set(packets))}")
            
            if connection in self.suspected_wireguard:
                print("STATUS: Likely WireGuard traffic")
                print("Detected patterns:")
                print("- Characteristic packet sizes")
                print("- Regular timing intervals")
            else:
                print("STATUS: No clear WireGuard indicators")

def main():
    detector = WireGuardDetector()
    
    print("Starting WireGuard Traffic Detection")
    print("This tool will analyze network traffic for WireGuard characteristics")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)


# Настройка конфигурации на уровень 3 (L3)
# conf.L3socket = conf.L3RawSocket


# sniff(count=10)

if __name__ == "__main__":
    main()