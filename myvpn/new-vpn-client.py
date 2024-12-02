import socket
from netfilterqueue import NetfilterQueue

# Симуляция шифрования
def encrypt(packet_data):
    return packet_data[::-1]  # Просто переворачиваем байты (для примера)

# Отправка пакета на сервер
def send_to_server(packet_data):
    server_address = ("SERVER_IP", 12345)  # Замените на IP вашего сервера
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)
        s.sendall(packet_data)

def process_packet(packet):
    payload = packet.get_payload()
    encrypted_payload = encrypt(payload)  # Шифруем пакет

    # Отправляем зашифрованный пакет на сервер
    send_to_server(encrypted_payload)

    # Пакет на уровне сетевого стека больше нам не нужен, его можно "дропнуть"
    packet.drop()

queue = NetfilterQueue()
try:
    queue.bind(10, process_packet)
    print("Client is running, capturing traffic...")
    queue.run()
except KeyboardInterrupt:
    print("Stopping...")
    queue.unbind()
