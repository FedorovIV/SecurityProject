## Раздача статических файлов nginx
```
sudo apt install nginx

sudo chown -R www-data:www-data /var/www/static-example
sudo chmod -R 755 /var/www/static-example

sudo nano /etc/nginx/sites-available/static-example

```

```
# ipv4
server {
    listen 80;

    server_name localhost; # Замените на ваш домен или IP-адрес, например, 88.119.170.154

    root /mnt/d/programing/SecurityProject/server/public;    # Путь к вашей директории со статикой
    index index.html;                # Индексный файл

    location / {
        try_files $uri $uri/ =404;
    }

    # Лог-файлы сервера
    access_log /var/log/nginx/static-example-access.log;
    error_log /var/log/nginx/static-example-error.log;
}
#ipv6
server {
    listen [::]:80 ipv6only=on;

    server_name localhost; # Замените на ваш домен или IP-адрес

    root /mnt/d/programing/SecurityProject/server/public;    # Путь к вашей директории со статикой
    index index.html;                # Индексный файл

    location / {
        try_files $uri $uri/ =404;
    }

    # Лог-файлы сервера
    access_log /var/log/nginx/static-example-access.log;
    error_log /var/log/nginx/static-example-error.log;
}

```


```
sudo ln -s /etc/nginx/sites-available/static-example /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx
```

```
curl -v http://[2001:db8::2]
```