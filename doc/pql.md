#Introdcution

#Packet generator

packet {
    eth {
        smac: 01:02:03:04:05:06
    }
    ipv4 {
        ip.dst: 192.168.3.230
    }
    tcp {
        dport: 443
    }
};


```
assert "Assert vlan data and vlan voip dot not communicate"
       count == 0 
       where ip.address == 192.168.3.0/24 and
             ip.address == 192.168.250.0/24 
       interval now to now - 1h
       every 1h

       count(field)|avg(field)|sum(field)

assert "Assert vlan data bandwidth"
       (avg(frame.incl_len) / 3600) < 10M
       where ip.src == 192.168.3.0/24 and tcp.port == HTTPS
       interval now to now - 1h
       every 1h
```
