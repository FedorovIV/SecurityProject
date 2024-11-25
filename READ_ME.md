## Измерение скорости на Linux
```
sudo apt install speedtest

speedtest
```

## Настройка виртуальных машин

A - клиент
B - menInTheMiddle
C - self-hosted vpn server

### настройка A:
Adapter 1:
Host only (Внутренняя сеть)

```
sudo ip route add default via ip_add_b dev eth0
```

ip_add_b - адрес сервера B во внутренней сети 
eth0 - название интрефейса машины A
### настройка B:

Adapter 1:
Host only (Внутренняя сеть)
Adapter 2:
Nat(Внешняя сеть)

```
sudo sysctl -w net.ipv4.ip_forward=1
sudo nano /etc/sysctl.conf
net.ipv4.ip_forward=1

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

sudo apt install iptables-persistent
sudo netfilter-persistent save
```
## Узнать ip адрес (Linux)

```
curl ifconfig.me
```