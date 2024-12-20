# IpSec
Как удалось выяснить, большинство встроенных протоколов VPN в Windows используют IpSec. Разберёмся как устроен IpSec

IPsec реализован на сетевом уровне (3-й уровень). Его основе находится три протокола:
- Authentication Header (AH) - отвечает за аунтентификацию источника информации
- Encapsulation Security Pauload (ESP) - обеспечивает шифрование передаваемой информации. 
- Internet Security Association and Key Management Protocol (ISAKMP) - протокол, используемый для первичной настройки соединения, взаимной аутентификации конечными узлами друг друга и обмена секретными ключами. Могут применяться различные механизмы обмена ключами, например протокол Internet Key Exchange, Kerberized Internet Negotiation of Keys (RFC 4430) или записей DNS типа IPSECKEY

Важный термин Security Association (SA) - набор папраметров, характеризующий соединение. Например, используемый алгоритм шифрования и хеш-функция, секретные ключи, номер пакета.

Бывает два режима

- Транспортный - шифруется или подписывается только содержимое пакета, исходный заголовок сохраняется. Нужен для установления соединения между хостами.   
- В туннельном режиме шифруется весь исходный пакет, то есть происходит инкапсуляция.

Установленное защищённое соединение называется SA (Security Association).
Что устанавливается в SA:
- Аутентификация сторон
- Будет ли шифрование, проверка целостности данных
- Выбор необходимого протокола AH или ESP передачи данных 
- Выбор конкретного алгоритма шифрования (для шифрования - DES, для хеш-функция MD5 либо SHA-1. Также могут быть коммерчиские алгоритмы шифрования: Triple DES, Blowfish, CAST)

Важно понимать, что на одном узле может быть несколько SA. Все они хранятся в SAD (Security Associations Database) IPsec-модуля

Конфигурация VPN на IKEv2 
https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-20-04-ru