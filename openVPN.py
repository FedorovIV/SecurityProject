from scapy.all import sniff, UDP, TCP, Raw, IP
from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple
from scapy.all import *

conf.ifaces.show()


class OpenVPNDetector:
    def __init__(self):
        self.setup_logging()
        self.connections: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        self.suspected_openvpn = set()
        self.packet_timestamps = defaultdict(list)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """Анализ отдельного пакета на признаки OpenVPN"""
        # OpenVPN может работать как по UDP, так и по TCP
        if IP in packet:
            print(packet[IP].src, packet[IP].dst)
            
        # if UDP in packet or TCP in packet:
        #     if UDP in packet:
        #         src = packet[UDP].sport
        #         dst = packet[UDP].dport
        #         proto = "UDP"
        #     else:
        #         src = packet[TCP].sport
        #         dst = packet[TCP].dport
        #         proto = "TCP"
            
        #     # Проверяем стандартные порты OpenVPN
        #     if src == 1194 or dst == 1194 or src == 443 or dst == 443:
        #         self.logger.info(f"Detected OpenVPN default port usage: {src} -> {dst} ({proto})")
        #         return True
            
        #     # Анализируем содержимое пакета
        #     if Raw in packet:
        #         payload = packet[Raw].load
        #         payload_size = len(payload)
        #         connection = (packet.src, packet.dst, proto)
                
        #         packet_info = {
        #             'size': payload_size,
        #             'time': time.time(),
        #             'payload': payload
        #         }
                
        #         # Сохраняем информацию о пакете
        #         self.connections[connection].append(packet_info)
        #         self.packet_timestamps[connection].append(time.time())
                
        #         # Проверяем характерные признаки OpenVPN
        #         if self.check_openvpn_patterns(connection):
        #             self.suspected_openvpn.add(connection)
        #             return True
        
        return False
    
    def check_openvpn_patterns(self, connection: Tuple[str, str, str]) -> bool:
        # """Проверка паттернов характерных для OpenVPN"""
        # packets = self.connections[connection]
        
        # if len(packets) < 5:
        #     return False
            
        # # Проверяем характерные признаки TLS handshake в OpenVPN
        # packet_sizes = [p['size'] for p in packets]
        
        # # Проверка на TLS Control Channel Security Parameter
        # has_control_packets = any(110 <= size <= 160 for size in packet_sizes)
        
        # # Проверка характерных размеров пакетов данных
        # data_packets = [size for size in packet_sizes if size > 160]
        # if data_packets:
        #     avg_data_size = sum(data_packets) / len(data_packets)
        #     has_data_pattern = 400 <= avg_data_size <= 1500  # Типичный размер для OpenVPN
        # else:
        #     has_data_pattern = False
            
        # # Проверка первых байтов пакетов (OpenVPN имеет характерную структуру)
        # for packet in packets[-5:]:  # Проверяем последние 5 пакетов
        #     payload = packet['payload']
        #     if len(payload) > 0:
        #         # Проверка опкодов OpenVPN
        #         opcode = payload[0] & 0x3F  # OpenVPN opcode в младших 6 битах
        #         if opcode in [1, 2, 3, 4, 5, 6, 7, 8]:  # Основные опкоды OpenVPN
        #             self.logger.info(f"Detected OpenVPN opcode: {opcode}")
        #             return True
        
        # # Проверка периодичности пакетов (keepalive)
        # if len(self.packet_timestamps[connection]) >= 2:
        #     intervals = [self.packet_timestamps[connection][i+1] - self.packet_timestamps[connection][i] 
        #                 for i in range(len(self.packet_timestamps[connection])-1)]
        #     avg_interval = sum(intervals) / len(intervals)
            
        #     # OpenVPN обычно отправляет keepalive каждые 10 секунд
        #     has_keepalive = 8 <= avg_interval <= 12
            
        #     if has_keepalive and (has_control_packets or has_data_pattern):
        #         return True
            
        return False

    def start_detection(self, interface=None, timeout=600):
        """Запуск обнаружения OpenVPN"""
        self.logger.info(f"Starting OpenVPN detection on interface: {interface or 'default'}")
        
        try:
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                timeout=timeout,
                store=0
            )
        except KeyboardInterrupt:
            self.logger.info("Detection stopped by user")

    
    def print_results(self):
        """Вывод результатов анализа"""
        print("\nOpenVPN Detection Results:")
        print("-" * 50)
        
        if not self.connections:
            print("No potential OpenVPN connections analyzed")
            return
            
        for connection, packets in self.connections.items():
            src, dst, proto = connection
            print(f"\nConnection: {src} -> {dst} ({proto})")
            print(f"Total packets: {len(packets)}")
            print(f"Unique packet sizes: {sorted(set(p['size'] for p in packets))}")
            
            if connection in self.suspected_openvpn:
                print("STATUS: Likely OpenVPN traffic")
                print("Detected patterns:")
                print("- Characteristic packet sizes")
                print("- Regular keepalive intervals")
                print("- OpenVPN protocol patterns")
            else:
                print("STATUS: No clear OpenVPN indicators")

def main():
    detector = OpenVPNDetector()
    
    print("Starting OpenVPN Traffic Detection")
    print("This tool will analyze network traffic for OpenVPN characteristics")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

if __name__ == "__main__":
    main()
