# Introdcution

# Packet generator

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

# PQL

## Basic command structure
```
select proto.field, [proto.field]
from sensor name
where <expression>
top n
offset n
interval yyyy-mm-dd hh:MM:ss to yyyy-mm-dd hh:MM:ss

```
## IPv4 search
Subnet search
```
select <fields>
from sensor
where ip.src == 192.168.3.230
```

## Subnet search
Subnet search
```
select <fields>
from sensor
where ip.src == 192.168.3.0/24
```
## Arrays example 1
Extract the first byte and compared it to 0x45
```
select <fields>
from sensor
where ip[0:1] == [0x45]
```

## Arrays example 2
Extract the identification field 2 bytes at offset 4

```
select <fields>
from sensor
where ip[4:2] == [0,1]
```
## Bit operations

### Bit AND
Apply bit mask and 

```
select <fields>
from sensor
where (ip[0:1] & 0xf0) == 4 
```
### Bit OR
Apply bit mask or 

```
select <fields>
from sensor
where (ip[0:1] | 0xf0) == 4 
```
### Bit XOR
Apply bit mask xor 

```
select <fields>
from sensor
where (ip[0:1] ^ 0xf0) == 0xb5 
```
### Bit shit
Apply bit shift right

```
select <fields>
from sensor
where (ip[0:1] >> 4) == 0x04 
```

Apply bit shift left

```
select <fields>
from sensor
where (ip[0:1] << 4) == 0x00 
```
