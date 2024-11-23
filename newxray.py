from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple
import statistics
import threading
from queue import Queue

class ImprovedDetector:
    def __init__(self):
        self.setup_logging()
        # Словарь для хранения информации о соединениях
        self.connections: Dict[Tuple[str, str], dict] = defaultdict(
            lambda: {
                'packets': [],
                'timestamps': [],
                'sizes': [],
                'detection_history': [],  # История обнаружений
                'confirmed': False,       # Подтвержденное обнаружение
                'last_update': time.time()
            }
        )
        self.packet_queue = Queue()
        self.is_running = True
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """Добавление пакета в очередь для анализа"""
        if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            self.packet_queue.put(packet)
            return True
        return False

    def process_packet(self, packet):
        """Детальный анализ пакета"""
        try:
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                return False

            # Уникальный идентификатор соединения
            connection = (
                f"{packet[IP].src}:{sport}",
                f"{packet[IP].dst}:{dport}",
                proto
            )

            # Получаем или создаем информацию о соединении
            conn_info = self.connections[connection]
            current_time = time.time()

            # Обновляем информацию о последней активности
            conn_info['last_update'] = current_time

            # Добавляем информацию о пакете
            if Raw in packet:
                payload = packet[Raw].load
                payload_size = len(payload)
                
                conn_info['packets'].append({
                    'size': payload_size,
                    'time': current_time,
                    'payload': payload[:20],  # Сохраняем только начало для анализа
                    'sport': sport,
                    'dport': dport
                })
                
                conn_info['timestamps'].append(current_time)
                conn_info['sizes'].append(payload_size)

                # Ограничиваем размер сохраняемой истории
                if len(conn_info['packets']) > 100:
                    conn_info['packets'] = conn_info['packets'][-100:]
                    conn_info['timestamps'] = conn_info['timestamps'][-100:]
                    conn_info['sizes'] = conn_info['sizes'][-100:]

                # Анализируем накопленные данные
                detection_result = self.analyze_connection(connection, conn_info)
                
                # Обновляем историю обнаружений
                conn_info['detection_history'].append(detection_result)
                if len(conn_info['detection_history']) > 10:
                    conn_info['detection_history'] = conn_info['detection_history'][-10:]

                # Проверяем стабильность обнаружения
                if self.check_detection_stability(conn_info['detection_history']):
                    conn_info['confirmed'] = True
                    self.logger.info(f"Confirmed protocol detection for {connection}")
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            return False

    def analyze_connection(self, connection, conn_info):
        """Анализ накопленной информации о соединении"""
        if len(conn_info['packets']) < 5:
            return False

        # Проверяем различные характеристики
        timing_score = self.check_timing_patterns(conn_info['timestamps'])
        size_score = self.check_size_patterns(conn_info['sizes'])
        payload_score = self.check_payload_patterns(conn_info['packets'])
        port_score = self.check_port_patterns(conn_info['packets'])

        # Взвешенная оценка
        total_score = (
            timing_score * 0.3 +
            size_score * 0.3 +
            payload_score * 0.2 +
            port_score * 0.2
        )

        return total_score > 0.6

    def check_timing_patterns(self, timestamps):
        """Анализ временных интервалов"""
        if len(timestamps) < 3:
            return 0

        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        try:
            # Вычисляем статистические характеристики
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else float('inf')
            
            # Оцениваем регулярность
            regularity_score = 1.0 / (1.0 + stdev_interval / mean_interval)
            
            return regularity_score
        except Exception:
            return 0

    def check_size_patterns(self, sizes):
        """Анализ размеров пакетов"""
        if not sizes:
            return 0

        try:
            # Вычисляем статистические характеристики
            mean_size = statistics.mean(sizes)
            unique_sizes = len(set(sizes))
            size_ratio = unique_sizes / len(sizes)
            
            # Проверяем характерные размеры пакетов
            typical_sizes = [s for s in sizes if 40 <= s <= 1500]
            size_score = len(typical_sizes) / len(sizes) if sizes else 0
            
            return (size_score + (1 - size_ratio)) / 2
        except Exception:
            return 0

    def check_payload_patterns(self, packets):
        """Анализ содержимого пакетов"""
        if not packets:
            return 0

        try:
            # Проверяем характерные паттерны в начале пакетов
            pattern_matches = 0
            for packet in packets:
                payload = packet['payload']
                if len(payload) >= 3:
                    # Проверяем характерные начальные байты
                    if (payload[0] in {0x16, 0x17} or  # TLS
                        payload.startswith(b'\x00\x00') or  # Возможный заголовок
                        payload[0] & 0x3f in {1, 2, 3, 4}):  # Характерные опкоды
                        pattern_matches += 1

            return pattern_matches / len(packets)
        except Exception:
            return 0

    def check_port_patterns(self, packets):
        """Анализ используемых портов"""
        if not packets:
            return 0

        try:
            # Проверяем использование характерных портов
            common_ports = {443, 80, 8080, 1194}
            port_matches = sum(1 for p in packets 
                             if p['sport'] in common_ports or p['dport'] in common_ports)
            return port_matches / len(packets)
        except Exception:
            return 0

    def check_detection_stability(self, history):
        """Проверка стабильности обнаружения"""
        if len(history) < 5:
            return False

        # Проверяем последние результаты
        recent_results = history[-5:]
        true_count = sum(1 for x in recent_results if x)
        
        # Требуем более 60% положительных результатов
        return true_count / len(recent_results) > 0.6

    def background_processor(self):
        """Фоновая обработка пакетов"""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.process_packet(packet)
            except Exception:
                continue

    def cleanup_old_connections(self):
        """Очистка старых соединений"""
        current_time = time.time()
        old_connections = [
            conn for conn, info in self.connections.items()
            if current_time - info['last_update'] > 300  # 5 минут
        ]
        for conn in old_connections:
            del self.connections[conn]

    def start_detection(self, interface=None, timeout=60):
        """Запуск обнаружения"""
        self.logger.info(f"Starting detection on interface: {interface or 'default'}")
        
        # Запускаем фоновый обработчик
        processor_thread = threading.Thread(target=self.background_processor)
        processor_thread.start()

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
            self.is_running = False
            processor_thread.join()
            self.cleanup_old_connections()
            self.print_results()

    def print_results(self):
        """Вывод результатов"""
        print("\nDetection Results:")
        print("-" * 50)
        
        if not self.connections:
            print("No connections analyzed")
            return
            
        for connection, info in self.connections.items():
            src, dst, proto = connection
            print(f"\nConnection: {src} -> {dst} ({proto})")
            print(f"Total packets: {len(info['packets'])}")
            
            if info['confirmed']:
                print("STATUS: Protocol detected (Confirmed)")
                print("Detection stability: High")
            elif info['detection_history']:
                positive_rate = sum(1 for x in info['detection_history'] if x) / len(info['detection_history'])
                print(f"STATUS: Detection rate: {positive_rate:.2%}")
            else:
                print("STATUS: No specific indicators")

def main():
    detector = ImprovedDetector()
    
    print("Starting Improved Protocol Detection")
    print("Press Ctrl+C to stop\n")
    
    interface = input("Enter network interface (press Enter for default): ").strip() or None
    detector.start_detection(interface=interface)

if __name__ == "__main__":
    main()
