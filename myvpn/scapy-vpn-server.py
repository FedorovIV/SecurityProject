from scapy.all import *
import socket

# Настройки туннеля
LOCAL_IP = "0.0.0.0"  # IP для прослушивания
LOCAL_PORT = 5555     # Порт для прослушивания

# Настраиваем сокет для получения UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))

def handle_tunnel():
    while True:
        data, addr = sock.recvfrom(65565)  # Получаем рау-пакет
        print(f"Пакет получен от {addr}")

        # Извлекаем IP-пакет из UDP-данных
        packet = IP(data)

        # Отправляем его дальше
        send(packet)

print(f"Запуск сервера на {LOCAL_IP}:{LOCAL_PORT}")
handle_tunnel()
