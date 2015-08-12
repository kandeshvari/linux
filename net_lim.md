# network limits control group

## ipv4.ports

Не использовать ограничения контрольной группы:

    # echo "" > net_lim.ipv4.ports

Разрешить определенные порты/диапазоны для bind():

    # echo "45,500,41000-45000" > net_lim.ipv4.ports


## ipv4.ip_local_port_range (read-only)

Используется последний порт/диапазон из списка `ipv4.ports`.

    cat net_lim.ipv4.ip_local_port_range 
    41000-45000    


## ipv4.addrs

Не использовать ограничения контрольной группы. Адреса не проверяются. Нет ограничений:

    # echo "" > net_lim.ipv4.addrs

Установить адреса разрешенные для bind():

    # echo "127.0.0.1,192.168.0.1" > net_lim.ipv4.addrs


## ipv4.default_address (read-only)

Используется первый адрес из списка `ipv4.addrs`.

    cat net_lim.ipv4.default_address
    127.0.0.1
