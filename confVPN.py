from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple
import statistics
import threading
from queue import Queue
import struct
from enum import Enum

class TLSRecordType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class TLSHandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

class ProtocolDetector:
    def __init__(self):
        self.setup_logging()
        self.connections = defaultdict(lambda: {
            'packets': [],
            'handshakes': [],
            'key_exchanges': [],
            'state': 'new',
            'last_update': time.time(),
            'detection_score': 0.0
        })
        self.packet_queue = Queue()
        self.is_running = True

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def process_packet(self, packet):
        """Обработка пакета"""
        try:
            if TCP in packet and Raw in packet and IP in packet:
                payload = bytes(packet[Raw])
                connection_id = (
                    f"{packet[IP].src}:{packet[TCP].sport}",
                    f"{packet[IP].dst}:{packet[TCP].dport}",
                    'TCP'
                )
                
                conn_data = self.connections[connection_id]
                conn_data['packets'].append({
                    'time': time.time(),
                    'size': len(payload),
                    'data': payload[:10]  # Сохраняем только начало для анализа
                })

                # Анализ TLS записи
                tls_info = self.analyze_tls_record(payload)
                if tls_info.get('is_valid_tls'):
                    handshake_info = None
                    if tls_info['type'] == TLSRecordType.HANDSHAKE.value:
                        handshake_info = self.analyze_handshake(tls_info.get('handshake_data', b''))
                        if handshake_info:
                            conn_data['handshakes'].append(handshake_info)
                            
                            # Анализ обмена ключами
                            if 'key_characteristics' in handshake_info:
                                conn_data['key_exchanges'].append(handshake_info)
                                
                            # Обновляем оценку обнаружения
                            conn_data['detection_score'] = self.calculate_detection_score(conn_data)
                            
                            if conn_data['detection_score'] > 0.8:  # Порог обнаружения
                                return True

                return self.check_protocol_patterns(conn_data)

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
        return False

    def check_protocol_patterns(self, conn_data: dict) -> bool:
        """Проверка паттернов протокола"""
        if len(conn_data['packets']) < 5:
            return False

        # Проверяем наличие рукопожатия
        has_handshake = any(h['type'] in 
            {TLSHandshakeType.CLIENT_HELLO.value, TLSHandshakeType.SERVER_HELLO.value} 
            for h in conn_data['handshakes'])

        # Проверяем обмен ключами
        has_key_exchange = any('key_characteristics' in h for h in conn_data['handshakes'])

        # Проверяем размеры пакетов
        packet_sizes = [p['size'] for p in conn_data['packets']]
        has_valid_sizes = (
            len(packet_sizes) > 5 and
            any(size > 1000 for size in packet_sizes) and  # Большие пакеты
            any(40 <= size <= 100 for size in packet_sizes)  # Маленькие пакеты
        )

        return has_handshake and has_key_exchange and has_valid_sizes

    def calculate_detection_score(self, conn_data: dict) -> float:
        """Расчет оценки обнаружения"""
        score = 0.0
        
        # Оценка рукопожатия
        handshake_types = {h.get('type') for h in conn_data['handshakes']}
        if TLSHandshakeType.CLIENT_HELLO.value in handshake_types:
            score += 0.3
        if TLSHandshakeType.SERVER_HELLO.value in handshake_types:
            score += 0.3

        # Оценка обмена ключами
        if conn_data['key_exchanges']:
            key_score = sum(
                1 for ke in conn_data['key_exchanges']
                if ke.get('key_characteristics', [])
            ) / len(conn_data['key_exchanges'])
            score += key_score * 0.4

        return min(score, 1.0)

    def start_detection(self, interface=None, timeout=60):
        """Запуск обнаружения"""
        self.logger.info(f"Starting detection on interface: {interface or 'default'}")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                timeout=timeout,
                store=0
            )
        except KeyboardInterrupt:
            self.logger.info("Detection stopped by user")
        finally:
            self.print_results()

    def print_results(self):
        """Вывод результатов"""
        print("\nDetection Results:")
        print("-" * 50)
        
        if not self.connections:
            print("No connections analyzed")
            return
            
        for connection_id, conn_data in self.connections.items():
            src, dst, proto = connection_id
            print(f"\nConnection: {src} -> {dst} ({proto})")
            print(f"Total packets: {len(conn_data['packets'])}")
            print(f"Handshakes detected: {len(conn_data['handshakes'])}")
            print(f"Key exchanges detected: {len(conn_data['key_exchanges'])}")
            print(f"Detection score: {conn_data['detection_score']:.2f}")
            
            if conn_data['handshakes']:
                print("\nHandshake Types:")
                handshake_types = Counter(h.get('type') for h in conn_data['handshakes'])
                for htype, count in handshake_types.items():
                    print(f"- Type {htype}: {count} times")
            
            if conn_data['key_exchanges']:
                print("\nKey Exchange Characteristics:")
                for ke in conn_data['key_exchanges']:
                    if 'key_characteristics' in ke:
                        print(f"- {ke['key_type']}: {', '.join(ke['key_characteristics'])}")

def main():
    detector = ProtocolDetector()
    
    print("Starting Protocol Detection")
    print("This tool will analyze network traffic patterns")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

if __name__ == "__main__":
    main()