use byteorder::{BigEndian, ByteOrder};

pub const IP_HDR_LEN_POS: usize = 0x0e;
pub const TCP_HDR_LEN_POS: usize = 0x2e;

pub const ETHERNET_HDR_LEN: usize = 0x0e;
pub const UDP_HEADER_LEN: u8 = 8;

const ETHER_IPV4_PROTO: u16 = 0x0800;
// const ETHER_IPV6_PROTO: u16 = 0x08DD;
// const ETHER_ARP_PROTO: u16 = 0x0806;
const ETHER_8021Q: u16 = 0x8100;

const IP_TCP_PROTO: u8 = 0x06;
const IP_UDP_PROTO: u8 = 0x11;
// const IP_ICMP_PROTO: u8 = 0x01;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRef {
    ts_sec: u32,
    ts_usec: u32,
    inc_len: u32,
    orig_len: u32,
    pkt_ptr: usize,
    file_ptr: usize,
    raw_packet: Vec<u8>,
    vo: usize,
}

impl PacketRef {
    pub fn new(
        inc_len: u32,
        orig_len: u32,
        ts_sec: u32,
        ts_usec: u32,
        pkt_ptr: usize,
        file_ptr: usize,
    ) -> Self {
        Self {
            inc_len,
            orig_len,
            ts_sec,
            ts_usec,
            pkt_ptr,
            file_ptr,
            vo: 0,
            raw_packet: vec![0],
        }
    }

    pub fn set_packet(&mut self, packet: &[u8]) {
        self.raw_packet = packet.to_vec();
        if self.ether_header() == ETHER_8021Q {
            self.vo = 4;
        }
    }

    pub fn vlan_id(&self) -> u16 {
        let mut vlan: u16 = 1;

        if self.ether_header() == ETHER_8021Q {
            vlan = BigEndian::read_u16(&self.raw_packet[14..16]);
            // vlan = (self.raw_packet[14] as u16) << 8;
            // vlan += self.raw_packet[15] as u16;
        }

        vlan
    }

    pub fn timestamp(&self) -> u32 {
        self.ts_sec
    }

    pub fn pkt_ptr(&self) -> usize {
        self.pkt_ptr
    }

    pub fn file_ptr(&self) -> usize {
        self.file_ptr
    }

    pub fn _pkt_header(&mut self, header_only: bool) -> [u8; 16] {
        let mut header: [u8; 16] = [0; 16];

        //--- Time second
        header[0] = ((self.ts_sec & 0xff000000) >> 24) as u8;
        header[1] = ((self.ts_sec & 0x00ff0000) >> 16) as u8;
        header[2] = ((self.ts_sec & 0x0000ff00) >> 8) as u8;
        header[3] = (self.ts_sec & 0x000000ff) as u8;

        //--- Time micro-second
        header[4] = ((self.ts_usec & 0xff000000) >> 24) as u8;
        header[5] = ((self.ts_usec & 0x00ff0000) >> 16) as u8;
        header[6] = ((self.ts_usec & 0x0000ff00) >> 8) as u8;
        header[7] = (self.ts_usec & 0x000000ff) as u8;

        //--- Included length
        if header_only {
            self.inc_len = self._get_header_len() as u32;
        }

        header[8] = ((self.inc_len & 0xff000000) >> 24) as u8;
        header[9] = ((self.inc_len & 0x00ff0000) >> 16) as u8;
        header[10] = ((self.inc_len & 0x0000ff00) >> 8) as u8;
        header[11] = (self.inc_len & 0x000000ff) as u8;

        //--- Actual length
        header[12] = ((self.orig_len & 0xff000000) >> 24) as u8;
        header[13] = ((self.orig_len & 0x00ff0000) >> 16) as u8;
        header[14] = ((self.orig_len & 0x0000ff00) >> 8) as u8;
        header[15] = (self.orig_len & 0x000000ff) as u8;

        return header;
    }

    // fn get_mac(&self, raw_mac: &[u8]) -> u64 {
    //     let mut mac_addr: u64;

    //     mac_addr = ((raw_mac[0] as u64) & 0x00000000000000ff) << 40;
    //     mac_addr += ((raw_mac[1] as u64) & 0x00000000000000ff) << 32;
    //     mac_addr += ((raw_mac[2] as u64) & 0x00000000000000ff) << 24;
    //     mac_addr += ((raw_mac[3] as u64) & 0x00000000000000ff) << 16;
    //     mac_addr += ((raw_mac[4] as u64) & 0x00000000000000ff) << 8;
    //     mac_addr += (raw_mac[5] as u64) & 0x00000000000000ff;

    //     mac_addr
    // }

    fn _get_mac_str(&self, raw_mac: &[u8]) -> String {
        let mac_str = format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            raw_mac[0], raw_mac[1], raw_mac[2], raw_mac[3], raw_mac[4], raw_mac[5],
        );

        mac_str
    }

    pub fn dst_mac(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[0..6])
        // self.get_mac(&self.raw_packet[0..6])
    }

    pub fn src_mac(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[6..12])
        // self.get_mac(&self.raw_packet[6..12])
    }

    pub fn _dst_mac_str(&self) -> String {
        self._get_mac_str(&self.raw_packet[0..6])
    }

    pub fn _src_mac_str(&self) -> String {
        self._get_mac_str(&self.raw_packet[6..12])
    }

    pub fn ether_header(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[12..14])
        // let mut etype: u16;

        // etype = (self.raw_packet[12] as u16) << 8;
        // etype += self.raw_packet[13] as u16;

        // etype
    }

    pub fn ether_type(&self) -> u16 {
        if self.ether_header() != ETHER_8021Q {
            BigEndian::read_u16(&self.raw_packet[12..14])
        } else {
            BigEndian::read_u16(&self.raw_packet[16..18])
        }
        // let mut etype: u16;

        // if self.ether_header() != ETHER_8021Q {
        //     etype = (self.raw_packet[12] as u16) << 8;
        //     etype += self.raw_packet[13] as u16;
        // } else {
        //     etype = (self.raw_packet[16] as u16) << 8;
        //     etype += self.raw_packet[17] as u16;
        // }
        // etype
    }

    // fn get_ip(&self, raw_ip: &[u8]) -> u32 {
    //     let mut ip_addr: u32;

    //     ip_addr = (raw_ip[0] as u32) << 24;
    //     ip_addr += (raw_ip[1] as u32) << 16;
    //     ip_addr += (raw_ip[2] as u32) << 8;
    //     ip_addr += raw_ip[3] as u32;

    //     ip_addr
    // }

    fn _get_ip_str(&self, raw_ip: &[u8]) -> String {
        let ip_str = format!("{}.{}.{}.{}", raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3]);

        ip_str
    }

    pub fn _src_ip_str(&self) -> String {
        self._get_ip_str(&self.raw_packet[26..30])
    }

    pub fn _dst_ip_str(&self) -> String {
        self._get_ip_str(&self.raw_packet[30..34])
    }

    pub fn src_ip(&self) -> u32 {
        if self.ether_type() == ETHER_IPV4_PROTO {
            BigEndian::read_u32(&self.raw_packet[30..34])
            // self.get_ip(&self.raw_packet[30..34])
            // self.get_ip(&self.raw_packet[26..30])
        } else {
            0
        }
    }

    pub fn dst_ip(&self) -> u32 {
        if self.ether_type() == ETHER_IPV4_PROTO {
            BigEndian::read_u32(&self.raw_packet[34..38])
            // self.get_ip(&self.raw_packet[34..38])
        } else {
            0
        }
    }

    pub fn ip_proto(&self) -> u8 {
        // let mut ip_proto: u8 = 0;

        if self.ether_type() == ETHER_IPV4_PROTO {
            self.raw_packet[23 + self.vo] as u8
            // ip_proto = self.raw_packet[23 + self.vo];
        } else {
            0 as u8
        }

        // ip_proto
    }

    pub fn sport(&self) -> u16 {
        // let mut port: u16 = 0;

        if self.ip_proto() == IP_UDP_PROTO || self.ip_proto() == IP_TCP_PROTO {
            BigEndian::read_u16(&self.raw_packet[34 + self.vo..36 + self.vo])
            // port = (self.raw_packet[34 + self.vo] as u16) << 8;
            // port += self.raw_packet[35 + self.vo] as u16;
        } else {
            0 as u16
        }

        // port
    }

    pub fn dport(&self) -> u16 {
        // let mut port: u16 = 0;

        if self.ip_proto() == IP_UDP_PROTO || self.ip_proto() == IP_TCP_PROTO {
            BigEndian::read_u16(&self.raw_packet[36 + self.vo..38 + self.vo])
            // port = (self.raw_packet[36 + self.vo] as u16) << 8;
            // port += self.raw_packet[37 + self.vo] as u16;
        } else {
            0 as u16
        }

        // port
    }

    pub fn _get_payload(&self) -> Vec<u8> {
        match self.ip_proto() {
            IP_TCP_PROTO => self.raw_packet[self._get_ip_header_len() as usize..].to_vec(),
            IP_UDP_PROTO => self.raw_packet[self._get_ip_header_len() as usize..].to_vec(),
            _ => self.raw_packet.to_vec(),
        }
    }

    pub fn _get_ip_header_len(&self) -> u8 {
        let hdr_len = self.raw_packet[IP_HDR_LEN_POS];

        (hdr_len >> 4) * 4
    }

    pub fn _get_udp_header_len(&self) -> u8 {
        return UDP_HEADER_LEN;
    }

    pub fn _get_tcp_header_len(&self) -> u8 {
        (self.raw_packet[TCP_HDR_LEN_POS] >> 4) * 4
    }

    pub fn _get_header_len(&self) -> u16 {
        //--- ethernet: 0x0d
        //--- ip header len: 0x0e
        //--- TCP header len position: 0x2e
        //--- UDP end of header: 0x29

        match self.ip_proto() {
            0x06 => {
                ETHERNET_HDR_LEN as u16
                    + self._get_ip_header_len() as u16
                    + self._get_tcp_header_len() as u16
            }
            0x11 => {
                (ETHERNET_HDR_LEN as u16 + self._get_ip_header_len() as u16 + UDP_HEADER_LEN as u16)
                    as u16
            }
            _ => self.inc_len as u16,
        }
    }

    pub fn _get_data_len(&self) -> u16 {
        self.raw_packet.len() as u16 - self._get_header_len()
    }

    pub fn _get_header(&mut self) -> Vec<u8> {
        let hdr_len: u32 = self._get_header_len() as u32;

        self.inc_len = hdr_len;

        self.raw_packet[0..hdr_len as usize].to_vec()
    }

    pub fn _get_packet(&mut self, header: bool) -> Vec<u8> {
        if header {
            self._get_header().to_vec()
        } else {
            self.raw_packet.to_vec()
        }
    }
}
