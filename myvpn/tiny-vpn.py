#!/usr/bin/env python3
import os
import fcntl
import struct
import socket
import select 
import hashlib
import zlib
import time
import threading
from cryptography.fernet import Fernet

# Константы для создания TUN
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun(name, ip):
    # Создаем TUN интерфейс
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    
    # Настраиваем интерфейс
    os.system(f'ip addr add {ip}/24 dev {name}')
    os.system(f'ip link set dev {name} up')
    
    return tun

class VPN:
    def __init__(self, password, compression_level=6):
        # Генерируем ключ шифрования из пароля
        key = hashlib.sha256(password.encode()).digest()
        self.cipher = Fernet(Fernet.generate_key())
        self.compression_level = compression_level
        
    def compress(self, data):
        return zlib.compress(data, self.compression_level)
        
    def decompress(self, data):
        return zlib.decompress(data)
        
    def encrypt(self, data):
        # Сначала сжимаем, потом шифруем
        compressed = self.compress(data)
        return self.cipher.encrypt(compressed)
        
    def decrypt(self, data):
        try:
            # Сначала расшифровываем, потом распаковываем
            decrypted = self.cipher.decrypt(data)
            return self.decompress(decrypted)
        except:
            return None

class VPNClient:
    def __init__(self, local_ip, server_ip, server_port, password):
        self.local_ip = local_ip
        self.server = (server_ip, server_port)
        self.vpn = VPN(password)
        self.running = False
        self.connected = False
        self.reconnect_interval = 5  # начальный интервал
        self.max_reconnect_interval = 60  # максимальный интервал
        
    def setup_connection(self):
        # Создаем UDP сокет
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Создаем TUN
        self.tun = create_tun('tun0', self.local_ip)
        
        # Добавляем маршрут через VPN
        os.system(f'ip route add default via {self.local_ip}')
        
    def reconnect(self):
        while self.running and not self.connected:
            try:
                print(f'[*] Подключение к серверу {self.server[0]}:{self.server[1]}...')
                # Создаем новый сокет
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Отправляем инициализационный пакет
                self.sock.sendto(self.vpn.encrypt(b'init'), self.server)
                
                # Ждем ответ от сервера
                self.sock.settimeout(5)
                data, _ = self.sock.recvfrom(64)
                if self.vpn.decrypt(data) == b'ok':
                    print('[+] Подключено!')
                    self.connected = True
                    self.reconnect_interval = 5  # сбрасываем интервал
                    self.sock.settimeout(None)
                    return True
                    
            except socket.error:
                interval = min(self.reconnect_interval, self.max_reconnect_interval)
                print(f'[!] Ошибка подключения. Повторная попытка через {interval} сек')
                time.sleep(interval)
                self.reconnect_interval *= 1.5  # увеличиваем интервал
                
        return False
        
    def handle_traffic(self):
        while self.running:
            try:
                # Ждем данные от TUN или сокета
                r, _, _ = select.select([self.sock, self.tun], [], [], 1)
                
                for fd in r:
                    if fd is self.sock:
                        # Данные от сервера
                        data, _ = self.sock.recvfrom(4096)
                        packet = self.vpn.decrypt(data)
                        if packet:
                            os.write(self.tun, packet)
                            
                    if fd is self.tun:
                        # Данные из TUN
                        packet = os.read(self.tun, 4096)
                        encrypted = self.vpn.encrypt(packet)
                        self.sock.sendto(encrypted, self.server)
                        
            except (socket.error, IOError) as e:
                print(f'[!] Ошибка передачи данных: {e}')
                self.connected = False
                if self.reconnect():
                    continue
                else:
                    break
                    
    def start(self):
        self.running = True
        self.setup_connection()
        
        # Запускаем поток переподключения
        reconnect_thread = threading.Thread(target=self.reconnect)
        reconnect_thread.start()
        
        # Ждем успешного подключения
        while self.running and not self.connected:
            time.sleep(0.1)
            
        if self.connected:
            # Запускаем обработку трафика
            self.handle_traffic()
            
        self.running = False
        reconnect_thread.join()
        
    def stop(self):
        self.running = False
        self.sock.close()
        os.close(self.tun)

class VPNServer:
    def __init__(self, local_ip, port, password):
        self.local_ip = local_ip
        self.port = port
        self.vpn = VPN(password)
        
    def run(self):
        # Создаем UDP сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.port))
        
        # Создаем TUN
        tun = create_tun('tun0', self.local_ip)
        
        # Включаем форвардинг
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        os.system(f'iptables -t nat -A POSTROUTING -s {self.local_ip}/24 -j MASQUERADE')
        
        print(f'[*] VPN сервер запущен на {self.local_ip}:{self.port}')
        
        client_addr = None
        while True:
            try:
                # Ждем данные
                r, _, _ = select.select([sock, tun], [], [])
                
                for fd in r:
                    if fd is sock:
                        # Данные от клиента
                        data, addr = sock.recvfrom(4096)
                        packet = self.vpn.decrypt(data)
                        
                        if packet == b'init':
                            # Новое подключение
                            client_addr = addr
                            print(f'[+] Новый клиент: {addr[0]}:{addr[1]}')
                            sock.sendto(self.vpn.encrypt(b'ok'), addr)
                        elif packet and addr == client_addr:
                            # Обычный пакет от известного клиента
                            os.write(tun, packet)
                            
                    if fd is tun and client_addr:
                        # Данные из TUN
                        packet = os.read(tun, 4096)
                        encrypted = self.vpn.encrypt(packet)
                        sock.sendto(encrypted, client_addr)
                        
            except (socket.error, IOError) as e:
                print(f'[!] Ошибка: {e}')
                if client_addr:
                    print(f'[!] Клиент отключен: {client_addr[0]}:{client_addr[1]}')
                    client_addr = None

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['server', 'client'])
    parser.add_argument('--local-ip', required=True)
    parser.add_argument('--server-ip')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--password', required=True)
    args = parser.parse_args()

    try:
        if args.mode == 'server':
            server = VPNServer(args.local_ip, args.port, args.password)
            server.run()
        else:
            if not args.server_ip:
                print('Для клиента нужен --server-ip')
                return
            client = VPNClient(args.local_ip, args.server_ip, args.port, args.password)
            client.start()
    except KeyboardInterrupt:
        print('\n[*] Выключение')

if __name__ == '__main__':
    main()
