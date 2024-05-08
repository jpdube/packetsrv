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

# Assert definition

```sql

define "Data and VoIP cross check"
       assert nbr_packets == 0
       select count(*) as nbr_packets
       from a
       where ip.address == 192.168.3.0/24 and
             ip.address == 192.168.53.0/24

```

```sql

define "Data average bandwidth < 10Mbps fro HTTPS"
       assert bw <= 10M
       select bandwidth(frame.origlen) as bw
       from a
       where ip.address == 192.168.3.0/24 and
             tcp.dport == HTTPS
             
       interval now to now - 10m

```

```sql
assert "Assert vlan data and vlan voip dot not communicate"
       select ip.src, ip.dst
       from a
       where ip.address == 192.168.3.0/24 and
             ip.address == 192.168.250.0/24 and 
       having count() == 0
       
message "Found packet crossing vlan boundaries {result}"
notify it_admin

#-- Imply adding now to now -2h to sql 
every 2h 
```

```sql
assert "Assert vlan data bandwidth"
       (avg(frame.incl_len) / 3600) < 10M
       where ip.src == 192.168.3.0/24 and tcp.port == HTTPS
       interval now to now - 1h
       every 1h
```

# PQL

## Basic command structure
```sql
select proto.field, [proto.field]
from sensor name
where <expression>
top n
offset n
interval yyyy-mm-dd hh:MM:ss to yyyy-mm-dd hh:MM:ss

```
## IPv4 search
Subnet search
```sql
select <fields>
from sensor
where ip.src == 192.168.3.230
```

## Subnet search
Subnet search
```sql
select <fields>
from sensor
where ip.src == 192.168.3.0/24
```
## Arrays example 1
Extract the first byte and compared it to 0x45

```sql
select <fields>
from sensor
where ip[0:1] == [0x45]
```

## Arrays example 2
Extract the identification field 2 bytes at offset 4

```sql
select <fields>
from sensor
where ip[4:2] == [0,1]
```
## Interval
###Interval with dates

You can use full dates in the intervals

```sql
select <field>
from sensor
where <condition>
interval 2022-03-15 13:55:00 to 2022-03-15 14:05:00
top 10;

```

## Interval
###Interval with relative time

Relative time is very usefull in dashboard where you want to pull 
information at intervals

In PQL you can use the following modifiers:
s: second
m: minute
h: hour
d: day
w: week
M: monthe


The following example is unsing an interval from now to the last 30 seconds
```sql
select <field>
from sensor
where <condition>
interval now() to now(-30s)
top 10;

```

## Bit operations

### Bit AND
Apply bit mask and 

```sql
select <fields>
from sensor
where (ip[0:1] & 0xf0) == 4 
```
### Bit OR
Apply bit mask or 

```sql
select <fields>
from sensor
where (ip[0:1] | 0xf0) == 4 
```
### Bit XOR
Apply bit mask xor 

```sql
select <fields>
from sensor
where (ip[0:1] ^ 0xf0) == 0xb5 
```
### Bit shit
Apply bit shift right

```sql
select <fields>
from sensor
where (ip[0:1] >> 4) == 0x04 
```

Apply bit shift left

```sql
select <fields>
from sensor
where (ip[0:1] << 4) == 0x00 
```
## From sources

It's possible to use different sources in PQL. For exmaple, you could query the packet database and join with a json file or another a log file.

Example:
```sql
from source.format  #--- where source is the source of the data and 
                    #--- the format is packet if absent or otherwise
                    #--- a file name
```

### Json format

This is a good example were we can parse the file and obtain the fields and the data from the same file

