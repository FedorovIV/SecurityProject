
import asyncio
import websockets
from scapy.all import sniff, raw, sendp, Ether

INTERFACE = "eth0"  # Замените на ваш интерфейс VPN

connected_clients = set()

async def websocket_handler(websocket, path):
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            pkt = Ether(message)
            sendp(pkt, iface=INTERFACE, verbose=False)
    except Exception as e:
        print(f"WebSocket ошибка: {e}")
    finally:
        connected_clients.remove(websocket)

def packet_callback(packet):
    # Выводим пакет на экран
    # Детальный вывод полей пакета
    packet.show()
    # Или можно вывести сырые данные
    # print(raw(packet))
    # Если нужно декодировать как текст (осторожно, может быть бинарный мусор)
    # print(raw(packet).decode('utf-8', errors='replace'))

    pkt_bytes = raw(packet)
    asyncio.run_coroutine_threadsafe(broadcast_packet(pkt_bytes), asyncio.get_event_loop())

async def broadcast_packet(pkt_bytes):
    if connected_clients:
        await asyncio.wait([ws.send(pkt_bytes) for ws in connected_clients])

async def main():
    server = await websockets.serve(websocket_handler, "0.0.0.0", 8765)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sniff, {"iface": INTERFACE, "prn": packet_callback, "store": False})
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Остановка перехватчика пакетов...")
