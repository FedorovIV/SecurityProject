### Установка make and openSSL
```
sudo apt install build-essential
sudo apt install libssl-dev

```
### Установка nginx
```
sudo apt install nginx
```

## Конфигурация nginx для wss
```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;


events {
    worker_connections 768;
    # multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    # Конфигурация HTTPS
    server {
        listen 443 ssl http2; # SSL c поддержкой HTTP/2
        server_name 88.119.170.154; # Укажите ваш IP или домен

        # Пути к SSL-сертификату и приватному ключу
        ssl_certificate /etc/ssl/certs/ca-server.crt;
        ssl_certificate_key /etc/ssl/private/ca-server.key;

        ssl_verify_client on;
        ssl_client_certificate /etc/ssl/certs/client.crt;


        # Опциональные настройки SSL для повышения безопасности
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Настройка доступа к вашему VPN-серверу через HTTPS/WSS
        location /vpn {
            include uwsgi_params;
            uwsgi_pass unix:/run/vpn.sock;
        }
    }

}

```

## Конфигурация для ws 
```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    server {
        listen       80;
        server_name  88.119.170.154;

        # Настройка доступа к вашему VPN-серверу
        location /vpn {
            include uwsgi_params;
            uwsgi_pass unix:/run/vpn.sock;
        }
    }
}

```

### Проверка корректной настройки nginx
```
nginx -t
```
### Перезагрузка nginx
```
sudo systemctl reload nginx
```
### Подключитья с Windows
```
./vpn-ws-client foobar ws://88.119.170.154/vpn
``` 
### Подключиться с Linux
```
./vpn-ws-client vpn-ws0 ws://88.119.170.154/vpn
```

### Подключиться с Linux по сертификатам
```
sudo ./vpn-ws-client --key client.key --crt client.crt --exec "dhclient vpn2 &" vpn2 wss://88.119.170.154:443/vpn
```
### Настройка ipv4 интерфейса Linux
```
sudo ip addr add 169.254.58.208/16 dev vpn0
sudo ip link set vpn0 up

```

### Настройка сервера на перессылку пакетов
```
sudo nano /etc/sysctl.conf
net.ipv4.ip_forward=1

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

```

### Отключить firewall

```
sudo ufw disaebl
```

### Exe trick
```
./vpn-ws-client --exec "ifconfig vpn-ws0 192.168.10.2 netmask 255.255.255.0" vpn-ws0 ws://88.119.170.154/vpn
sudo ./vpn-ws-client --exec "dhclient user1 &" user1 --bridge ws://88.119.170.154/vpn
 ```

## DHCP конфигурация

```
sudo apt install isc-dhcp-server
sudo nano /etc/dhcp/dhcpd.conf

subnet 192.168.12.0 netmask 255.255.255.0 {
    range 192.168.12.100 192.168.12.200;  # Диапазон доступных адресов для клиентов
    option routers 192.168.12.1;         # IP шлюза (маршрутизатор)
    option domain-name-servers 8.8.8.8, 8.8.4.4; # DNS-серверы
    option domain-name "example.com";   # Доменное имя (опционально)
    default-lease-time 600;            # Время аренды IP (в секундах)
    max-lease-time 7200;               # Максимальное время аренды
}

sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf # Проверка валидности конфига

sudo nano /etc/default/isc-dhcp-server
INTERFACESv4="vpn0"

sudo systemctl start isc-dhcp-server
sudo systemctl enable isc-dhcp-server

sudo systemctl status isc-dhcp-server  # для Debian/Ubuntu

sudo systemctl restart isc-dhcp-server

sudo ip addr add 192.168.12.1/24 dev vpn2
sudo ip link set vpn2 up
```

### 
Добавил --tuntap, --bridge и установил
```
sudo apt install bridge-utils
```

### Рабочая конфа для пинга 
```
#Сервер
sudo ./vpn-ws --bridge --tuntap vpn-host2 /run/vpn.sock 

#Клиент
sudo ./vpn-ws-client --exec "dhclient user1 &" user1 --bridge ws://88.119.170.154/vpn 
```

### Поднять интерфейс после установки соед 
```
#ipv4
sudo ./vpn-ws-client --exec "ip addr add 192.168.1.100/24 dev user1; ip link set dev user1 up" user1 --bridge ws://88.119.170.154/vpn
#ipv6 ИМБААААААААААААААААААААААА
sudo ./vpn-ws-client --exec "ip -6 addr add 2001:db8::1/64 dev user1; ip link set dev user1 up" user1 --bridge ws://88.119.170.154/vpn

# wss
sudo ./vpn-ws-client --key ./certs/client.key --crt ./certs/client.crt --no-verify --exec "ip -6 addr add 2001:db8::1/64 dev user1; ip link set dev user1 up" user1 --bridge wss://88.119.170.154:443/vpn
```

### Настройка перессылки 
TODO

### Создание сертификатов
```
# Создаем приватный ключ CA
openssl genrsa -out ca-server.key 4096

# Создаем самоподписанный сертификат CA
openssl req -new -x509 -days 365 -key ca-server.key -out ca-server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=CA/CN=example-CA"


# Генерируем приватный ключ для клиента
openssl genrsa -out client.key 4096

# Создаем CSR для клиента
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Client/CN=Client"

# Подписываем клиентский сертификат
openssl x509 -req -in client.csr -CA ca-server.crt -CAkey ca-server.key -CAcreateserial -out client.crt -days 365

#На клиенте 
sudo cp server.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

```