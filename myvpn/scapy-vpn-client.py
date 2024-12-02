from scapy.all import *
import socket

# Настройки туннеля
REMOTE_IP = "88.119.170.154"  # IP сервера
REMOTE_PORT = 5555         # Порт сервера
LOCAL_INTERFACE = "Беспроводная сеть"   # Интерфейс источника (например, eth0)

# Настраиваем сокет для отправки UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def forward_packet(packet):
    # Перехват IP-пакета и инкапсуляция в UDP
    raw_data = raw(packet)
    sock.sendto(raw_data, (REMOTE_IP, REMOTE_PORT))

# Захватываем трафик с интерфейса и перенаправляем
print(f"Запуск туннеля. Отправка на {REMOTE_IP}:{REMOTE_PORT}")
sniff(iface=LOCAL_INTERFACE, filter="ip", prn=forward_packet)
