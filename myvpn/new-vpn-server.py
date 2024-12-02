import socket
from scapy.all import sendp, Ether

# Симуляция дешифрования
def decrypt(packet_data):
    return packet_data[::-1]  # Просто переворачиваем обратно

def inject_packet(packet_data):
    packet = Ether(packet_data)  # Создаем Ethernet-пакет
    sendp(packet, iface="eth0")  # Отправляем пакет в сеть (замените "eth0" на вашу сеть)

def start_server():
    server_address = ("0.0.0.0", 5554)  # Слушаем на всех IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(server_address)
        server.listen(5)
        print("Server is running...")
        
        while True:
            client_socket, client_address = server.accept()
            with client_socket:

                print(f"Connected by {client_address}")
                while True:
                    packet_data = client_socket.recv(4096)
                    if not packet_data:
                        break
                    decrypted_packet = decrypt(packet_data)  # Дешифруем пакет
                    inject_packet(decrypted_packet)  # Инжектируем в сеть

if __name__ == "__main__":
    start_server()
