import argparse
import time
from scapy.all import IP, Raw, send
import socket


def bit_flip(byte_array:bytearray, bit_position:bytearray) -> bytearray:
    """Инвертирует бит в указанной позиции."""
    res_byte_array = byte_array.copy()
    byte_index = bit_position // 8
    bit_index = bit_position % 8
    res_byte_array[byte_index] ^= 1 << bit_index
    return res_byte_array


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message", type=str, help="Origin message")
    parser.add_argument("-i", "--iterations", type=int, default=10, help="Number of iterations for averaging (default is 10)")
    parser.add_argument("-w", "--wait", type=int, default=10, help="Pause in ms between sending messages (default is 10 ms)")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address of the server where we send the message")

    args = parser.parse_args()

    byte_array = bytearray(args.message, 'utf-8')
    messages_list = [byte_array]
    num_bits = len(byte_array) * 8

    wait_in_sec = float(args.wait) / 1000
    
    for bit_pos in range(num_bits):
        messages_list.append(bit_flip(byte_array=byte_array, bit_position=bit_pos))

    for _ in range(args.iterations):        
        # ip_packet = IP(dst=args.ip)

        # for byte_message in messages_list:
        #     payload = Raw(load=byte_message)
        #     send(ip_packet / payload)
        #     time.sleep(wait_in_sec)
        port = 4431
        for byte_message in messages_list:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.sendto(byte_message, (args.ip, port))
            udp_socket.close()

if __name__ == "__main__":
    main()
