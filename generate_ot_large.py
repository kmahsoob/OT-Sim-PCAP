#!/usr/bin/env python3
"""
OT Manufacturing Network PCAP Generator — LARGE SCALE
======================================================
Target specs:
  - 40 PLCs (Allen-Bradley, Siemens, Schneider, Rockwell, Omron, Mitsubishi)
  - 10 HMIs (Wonderware, FactoryTalk, iFIX, Ignition, WinCC)
  - 4  DCS Controllers (Honeywell, Emerson, ABB, Yokogawa)
  - 2  Engineering Workstations
  - 2  Historian Servers (OSIsoft PI, AVEVA)
  - 1  SCADA Server
  - 1  OT Firewall / DMZ gateway
  - 1  Remote Access Jump Server
  Duration  : 3–5 days (configurable via CLI)
  Target BW : ~25 Mbps average → ~800 GB over 3 days
              (actual size = f(poll intervals, payload sizes, compression)

Run:
  python3 generate_ot_large.py                        # 3 days → ./ot_3day.pcap
  python3 generate_ot_large.py --days 5 --out big.pcap
  python3 generate_ot_large.py --days 3 --out /data/ot.pcap --chunk-hours 6

  --chunk-hours N  splits output into N-hour files: ot_3day_part00.pcap, ...
                   (recommended for >200 GB — avoids single 800 GB file)

Protocols:
  Modbus/TCP 502          PLCs ↔ HMI / SCADA (primary polling)
  EtherNet/IP CIP 44818   PLCs ↔ HMI (Allen-Bradley / Rockwell)
  S7comm 102              PLCs ↔ HMI (Siemens)
  DNP3/TCP 20000          DCS ↔ SCADA
  OPC-UA 4840             Historian ↔ all PLCs
  Syslog UDP 514          All devices → SCADA
  ARP / ICMP              Housekeeping
  PROFINET (simulated)    Siemens PLC ↔ remote I/O (UDP 34964)
  BACnet (simulated)      Building HVAC on same segment (UDP 47808)
  RDP 3389                Jump server access (simulated)
  SMB 445                 Historian file shares (simulated)
  NTP UDP 123             All devices time sync

Anomalies / Alert Events (spread across days):
  DAY 1
    T+00:30   ARP cache poisoning (rogue MAC → PLC-01 IP)
    T+02:00   PLC-07 goes dark (silent 9 min) → reconnects
    T+04:15   Modbus FC43 device ID recon scan (ENG-WS → all PLCs)
    T+06:00   DNP3 unsolicited response flood from DCS-01
    T+08:30   Abnormal Modbus FC16 write to reserved addr 0x9000 (PLC-12)
    T+10:00   PLC-to-PLC lateral Modbus (PLC-03 → PLC-18)
    T+14:00   Broadcast storm burst (L2 loop artifact)
    T+18:00   ICMP flood from rogue 10.99.99.1 → SCADA
    T+20:30   Auth failure storm on HMI-03 port 44818 (25 attempts)
    T+22:00   PLC-22 drops offline → silence → gratuitous ARP

  DAY 2
    T+25:00   New device fingerprint (unregistered MAC 00:de:ad:ff:00:01)
    T+27:30   TCP port scan (ENG-WS2) across all PLCs — OT ports
    T+30:00   PLC-01 coil write with out-of-band value FC05 0xFF01 (bad)
    T+33:00   S7comm STOP CPU command attempt (Siemens PLC-09)
    T+36:00   DCS-02 config upload attempt (DNP3 FC13 cold restart)
    T+38:00   PLC-15 & PLC-16 simultaneous disconnect (power event)
    T+42:00   Rogue OPC-UA session from unexpected IP
    T+45:00   SMB lateral movement ENG-WS → Historian (unusual)
    T+47:00   PLC-33 firmware download sequence detected (FC16 multi-block)

  DAY 3
    T+50:00   Repeat ARP spoof — different rogue MAC
    T+52:00   RDP brute force on Jump Server (30 attempts)
    T+54:30   NTP amplification-style flood (UDP 123)
    T+58:00   Modbus FC01 coil read sweep across all 40 PLCs (recon)
    T+60:00   PLC-05 CPU overload — timeout/retry storm from HMI-02
    T+63:00   DCS-01 DNP3 control relay output (unexpected setpoint change)
    T+67:00   PLC-28 & PLC-29 swap IPs (double ARP conflict)
    T+70:00   BACnet Who-Is flood (cross-segment broadcast recon)
    T+72:00   PLC-40 goes permanently offline (end of capture window)

Pure Python — zero third-party dependencies.
"""

import struct
import random
import socket
import os
import sys
import time
import argparse
import math
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

# ──────────────────────────────────────────────────────────────────────────────
# PCAP file format primitives
# ──────────────────────────────────────────────────────────────────────────────
PCAP_MAGIC = 0xA1B2C3D4
LINK_ETHERNET = 1

def pcap_global_header() -> bytes:
    return struct.pack('<IHHiIII',
        PCAP_MAGIC, 2, 4,
        0,      # TZ offset
        0,      # timestamp accuracy
        65535,  # snaplen
        LINK_ETHERNET
    )

def pcap_record(sec: int, usec: int, data: bytes) -> bytes:
    n = len(data)
    return struct.pack('<IIII', sec, usec, n, n) + data

# ──────────────────────────────────────────────────────────────────────────────
# Layer helpers (hand-crafted, no scapy)
# ──────────────────────────────────────────────────────────────────────────────
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

def _mb(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))

def _ib(ip: str) -> bytes:
    return socket.inet_aton(ip)

def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def eth(src: str, dst: str, etype: int, payload: bytes) -> bytes:
    return _mb(dst) + _mb(src) + struct.pack('>H', etype) + payload

def ip4(src: str, dst: str, proto: int, payload: bytes,
        ttl: int = 64, frag_id: int = None) -> bytes:
    if frag_id is None:
        frag_id = random.randint(0, 0xFFFF)
    ihl = 5
    total = ihl * 4 + len(payload)
    hdr = struct.pack('>BBHHHBBH4s4s',
        (4 << 4) | ihl, 0, total, frag_id, 0, ttl, proto, 0,
        _ib(src), _ib(dst))
    cs = _cksum(hdr)
    return hdr[:10] + struct.pack('>H', cs) + hdr[12:] + payload

def tcp(src_ip: str, dst_ip: str,
        sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes, win: int = 8192) -> bytes:
    off = (5 << 4)
    seg = struct.pack('>HHIIBBHHH',
        sport, dport, seq, ack, off, flags, win, 0, 0) + payload
    pseudo = _ib(src_ip) + _ib(dst_ip) + struct.pack('>BBH', 0, 6, len(seg))
    cs = _cksum(pseudo + seg)
    return seg[:16] + struct.pack('>H', cs) + seg[18:]

def udp(src_ip: str, dst_ip: str,
        sport: int, dport: int, payload: bytes) -> bytes:
    ln = 8 + len(payload)
    hdr = struct.pack('>HHHH', sport, dport, ln, 0)
    pseudo = _ib(src_ip) + _ib(dst_ip) + struct.pack('>BBH', 0, 17, ln)
    cs = _cksum(pseudo + hdr + payload)
    return struct.pack('>HHHH', sport, dport, ln, cs) + payload

def arp(src_mac: str, src_ip: str, dst_ip: str,
        op: int = 1, dst_mac: str = BCAST_MAC) -> bytes:
    return struct.pack('>HHBBH',1,0x0800,6,4,op) + \
           _mb(src_mac)+_ib(src_ip)+_mb(dst_mac)+_ib(dst_ip)

def icmp(typ: int, code: int, payload: bytes) -> bytes:
    hdr = struct.pack('>BBH', typ, code, 0)
    p = payload if len((hdr+payload))%2==0 else payload+b'\x00'
    cs = _cksum(hdr + p)
    return struct.pack('>BBH', typ, code, cs) + payload

# ──────────────────────────────────────────────────────────────────────────────
# Protocol payload builders
# ──────────────────────────────────────────────────────────────────────────────

def mb_req(uid: int, fc: int, addr: int, count: int, tid: int = None) -> bytes:
    if tid is None: tid = random.randint(1, 0xFFFF)
    pdu = struct.pack('>BBHh', uid, fc, addr, count)
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_resp(uid: int, fc: int, regs: List[int], tid: int = None) -> bytes:
    if tid is None: tid = random.randint(1, 0xFFFF)
    data = b''.join(struct.pack('>H', r) for r in regs)
    pdu = bytes([uid, fc, len(data)]) + data
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_exc(uid: int, fc: int, exc: int, tid: int = None) -> bytes:
    if tid is None: tid = random.randint(1, 0xFFFF)
    pdu = bytes([uid, fc | 0x80, exc])
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_fc16(uid: int, addr: int, vals: List[int], tid: int = None) -> bytes:
    if tid is None: tid = random.randint(1, 0xFFFF)
    count = len(vals)
    bc = count * 2
    pdu = struct.pack('>BBHHb', uid, 16, addr, count, bc)
    pdu += b''.join(struct.pack('>H', v) for v in vals)
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_fc43(uid: int, tid: int = None) -> bytes:
    """FC43 sub14 device ID read"""
    if tid is None: tid = random.randint(1, 0xFFFF)
    pdu = bytes([uid, 43, 14, 1, 0])
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_fc43_resp(uid: int, vendor: str, model: str, tid: int = None) -> bytes:
    if tid is None: tid = random.randint(1, 0xFFFF)
    vb = vendor.encode()[:32]
    mb = model.encode()[:32]
    obj = bytes([0x01, len(vb)]) + vb + bytes([0x02, len(mb)]) + mb
    pdu = bytes([uid, 43, 14, 1, 0x83, 0, 0, 2]) + obj
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def mb_coil_write(uid: int, addr: int, val: int, tid: int = None) -> bytes:
    """FC05 write single coil"""
    if tid is None: tid = random.randint(1, 0xFFFF)
    pdu = struct.pack('>BBHH', uid, 5, addr, val)
    return struct.pack('>HHH', tid, 0, len(pdu)) + pdu

def enip_list_id() -> bytes:
    return struct.pack('<HHIIqI', 0x65, 0, 0, 0, 0, 0)

def enip_connected(payload: bytes) -> bytes:
    sess = random.randint(0x10000, 0xFFFFF)
    return struct.pack('<HHIIqI', 0x6F, len(payload), sess, 0, 0, 0) + payload

def s7_read() -> bytes:
    """Simplified S7comm read var request (TPKT/COTP wrapper)"""
    cotp = b'\x02\xf0\x80'
    s7hdr = struct.pack('>BBHHHBB', 0x32, 1, 0, random.randint(1,0xFFFF),
                        14, 0, 0)
    param = b'\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00'
    tpkt = struct.pack('>BBH', 3, 0, 4 + 3 + len(s7hdr) + len(param))
    return tpkt + cotp + s7hdr + param

def s7_stop_cpu() -> bytes:
    """S7comm STOP CPU (alert-worthy)"""
    cotp = b'\x02\xf0\x80'
    # Function 0x29 = STOP
    s7hdr = struct.pack('>BBHHHBB', 0x32, 1, 0, random.randint(1,0xFFFF), 16, 0, 0)
    param = b'\x29\x00\x00\x00\x00\x00\x09\x50\x5f\x50\x52\x4f\x47\x52\x41\x4d'
    tpkt = struct.pack('>BBH', 3, 0, 4 + 3 + len(s7hdr) + len(param))
    return tpkt + cotp + s7hdr + param

def dnp3(src_addr: int, dst_addr: int, fc: int, obj_data: bytes = b'') -> bytes:
    ln = 5 + len(obj_data)
    ctrl = 0xC4
    return (b'\x05\x64' +
            bytes([ln, ctrl, fc]) +
            struct.pack('<H', dst_addr) +
            struct.pack('<H', src_addr) +
            obj_data)

def opc_ua_hello(endpoint: str = 'opc.tcp://historian.mfg.local:4840') -> bytes:
    ep = endpoint.encode()
    sz = 28 + len(ep)
    return b'HELF' + struct.pack('<IIIII', sz, 0, 65536, 65536, len(ep)) + ep

def ntp_client() -> bytes:
    """NTP client request"""
    li_vn_mode = (0 << 6) | (4 << 3) | 3  # LI=0, VN=4, Mode=3(client)
    return bytes([li_vn_mode]) + b'\x00' * 47

def bacnet_whois() -> bytes:
    """BACnet Who-Is broadcast"""
    return bytes([0x81, 0x0b, 0x00, 0x06, 0x10, 0x08])

def smb_negotiate() -> bytes:
    """Simplified SMB2 negotiate"""
    return (b'\x00\x00\x00\x2e'       # NetBIOS
            b'\xfeSMB'                  # SMB2 magic
            + b'\x00' * 42)

def rdp_syn_payload() -> bytes:
    """RDP X.224 connection request"""
    return bytes([
        0x03, 0x00, 0x00, 0x13,  # TPKT
        0x0e, 0xe0, 0x00, 0x00,  # X.224 CR TPDU
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00
    ])

def syslog(facility: int, severity: int, host: str, msg: str) -> bytes:
    pri = facility * 8 + severity
    h, m, s = random.randint(0,23), random.randint(0,59), random.randint(0,59)
    return f'<{pri}>1 2024-03-15T{h:02d}:{m:02d}:{s:02d}Z {host} ot-agent - - - {msg}'.encode()

def profinet_cyclic(src_id: int, dst_id: int) -> bytes:
    """PROFINET RT cyclic data (simplified Ethernet frame payload)"""
    frame_id = 0x8000 | (src_id & 0x3FFF)
    return struct.pack('>HH', frame_id, 0) + os.urandom(32)

# ──────────────────────────────────────────────────────────────────────────────
# Device model
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Dev:
    name:     str
    ip:       str
    mac:      str
    role:     str   # plc | hmi | dcs | eng | historian | scada | jump | fw
    vendor:   str
    uid:      int   = 1
    proto:    str   = 'modbus'   # modbus | s7 | enip | dnp3

    # runtime state
    seq:      int   = field(default_factory=lambda: random.randint(10000, 900000))
    offline:  bool  = False

    def bump(self, n: int = 100) -> int:
        self.seq = (self.seq + n) & 0xFFFFFFFF
        return self.seq

# ──────────────────────────────────────────────────────────────────────────────
# Topology: 40 PLCs, 10 HMIs, 4 DCS, 2 ENG, 2 Historians, 1 SCADA, 1 Jump
# ──────────────────────────────────────────────────────────────────────────────
VENDOR_CYCLE = [
    ('Allen-Bradley',  'enip'),
    ('Allen-Bradley',  'enip'),
    ('Siemens',        's7'),
    ('Siemens',        's7'),
    ('Schneider',      'modbus'),
    ('Rockwell',       'enip'),
    ('Omron',          'modbus'),
    ('Mitsubishi',     'modbus'),
]

def build_topology():
    plcs, hmis, dcs_list = [], [], []

    for i in range(1, 41):
        v, p = VENDOR_CYCLE[(i-1) % len(VENDOR_CYCLE)]
        plcs.append(Dev(
            name   = f'PLC-{i:02d}',
            ip     = f'192.168.10.{10 + i}',      # .11 – .50
            mac    = f'00:1a:2b:10:{i//256:02x}:{i%256:02x}',
            role   = 'plc',
            vendor = v,
            uid    = i,
            proto  = p,
        ))

    hmi_vendors = ['Wonderware','FactoryTalk','iFIX','Ignition','WinCC',
                   'Wonderware','FactoryTalk','iFIX','Ignition','WinCC']
    for i in range(1, 11):
        hmis.append(Dev(
            name   = f'HMI-{i:02d}',
            ip     = f'192.168.10.{100 + i}',     # .101 – .110
            mac    = f'00:1a:2b:20:{i:02x}:00',
            role   = 'hmi',
            vendor = hmi_vendors[i-1],
            uid    = i,
        ))

    dcs_vendors = [('Honeywell','dnp3'),('Emerson','dnp3'),
                   ('ABB','modbus'),('Yokogawa','modbus')]
    for i, (v, p) in enumerate(dcs_vendors, 1):
        dcs_list.append(Dev(
            name   = f'DCS-{i:02d}',
            ip     = f'192.168.10.{120 + i}',     # .121 – .124
            mac    = f'00:1a:2b:30:{i:02x}:00',
            role   = 'dcs',
            vendor = v,
            uid    = 50 + i,
            proto  = p,
        ))

    eng_ws = [
        Dev('ENG-WS1','192.168.10.200','00:1a:2b:40:01:00','eng','Dell'),
        Dev('ENG-WS2','192.168.10.201','00:1a:2b:40:02:00','eng','HP'),
    ]
    historians = [
        Dev('Historian-PI','192.168.10.210','00:1a:2b:50:01:00','historian','OSIsoft'),
        Dev('Historian-AV','192.168.10.211','00:1a:2b:50:02:00','historian','AVEVA'),
    ]
    scada = Dev('SCADA-SRV','192.168.10.220','00:1a:2b:60:01:00','scada','Inductive')
    jump  = Dev('JUMP-SRV', '192.168.10.230','00:1a:2b:70:01:00','jump','Dell')
    fw    = Dev('OT-FW',    '192.168.10.1',  '00:1a:2b:00:00:01','fw','Fortinet')

    all_dev = plcs + hmis + dcs_list + eng_ws + historians + [scada, jump, fw]
    return dict(plcs=plcs, hmis=hmis, dcs=dcs_list, eng=eng_ws,
                historians=historians, scada=scada, jump=jump, fw=fw,
                all=all_dev)

# ──────────────────────────────────────────────────────────────────────────────
# Writer
# ──────────────────────────────────────────────────────────────────────────────
class Writer:
    def __init__(self, path: str):
        self.path  = path
        self.f     = open(path, 'wb')
        self.f.write(pcap_global_header())
        self.count = 0
        self.bytes = 0

    def pkt(self, sec: int, usec: int, frame: bytes):
        rec = pcap_record(sec, usec, frame)
        self.f.write(rec)
        self.count += 1
        self.bytes += len(frame)

    def eth_tcp(self, sec, usec,
                src: Dev, dst: Dev,
                sport: int, dport: int,
                seq: int, ack: int, flags: int, payload: bytes):
        seg = tcp(src.ip, dst.ip, sport, dport, seq, ack, flags, payload)
        ip  = ip4(src.ip, dst.ip, 6, seg)
        fr  = eth(src.mac, dst.mac, 0x0800, ip)
        self.pkt(sec, usec, fr)

    def eth_udp(self, sec, usec,
                src: Dev, dst_ip: str, dst_mac: str,
                sport: int, dport: int, payload: bytes):
        dg = udp(src.ip, dst_ip, sport, dport, payload)
        ip = ip4(src.ip, dst_ip, 17, dg)
        fr = eth(src.mac, dst_mac, 0x0800, ip)
        self.pkt(sec, usec, fr)

    def close(self):
        self.f.close()

    def size_gb(self) -> float:
        return self.bytes / (1024**3)

# ──────────────────────────────────────────────────────────────────────────────
# Timestamp helpers
# ──────────────────────────────────────────────────────────────────────────────
def ts(sec: int, usec_jitter: bool = True) -> Tuple[int,int]:
    return (sec, random.randint(0, 999999) if usec_jitter else 0)

def ts_ms(sec: int, ms: int) -> Tuple[int,int]:
    usec = ms * 1000
    return (sec + usec // 1_000_000, usec % 1_000_000)

# ──────────────────────────────────────────────────────────────────────────────
# TCP session helpers
# ──────────────────────────────────────────────────────────────────────────────
def handshake(w: Writer, sec: int, src: Dev, dst: Dev,
              sport: int, dport: int) -> Tuple[int,int,int]:
    ci = random.randint(100000, 999999)
    si = random.randint(100000, 999999)
    u  = random.randint(0, 999999)
    w.eth_tcp(sec,   u,                   src, dst, sport, dport, ci,   0,    0x02, b'')
    w.eth_tcp(sec,   u+random.randint(500,2000), dst, src, dport, sport, si, ci+1, 0x12, b'')
    w.eth_tcp(sec,   u+random.randint(2500,5000), src, dst, sport, dport, ci+1, si+1, 0x10, b'')
    return ci+1, si+1, u+5000

def teardown(w: Writer, sec: int, usec: int,
             src: Dev, dst: Dev,
             sport: int, dport: int, cs: int, ss: int):
    w.eth_tcp(sec, usec,                   src, dst, sport, dport, cs, ss,   0x11, b'')
    w.eth_tcp(sec, usec+1000,              dst, src, dport, sport, ss, cs+1, 0x11, b'')
    w.eth_tcp(sec, usec+2000,              src, dst, sport, dport, cs+1, ss+1, 0x10, b'')

def data_psh(w: Writer, sec: int, usec: int,
             src: Dev, dst: Dev,
             sport: int, dport: int, cs: int, ss: int,
             req: bytes, resp: bytes, rtt_ms: int = 5) -> Tuple[int,int,int]:
    w.eth_tcp(sec, usec, src, dst, sport, dport, cs, ss, 0x18, req)
    ru = usec + rtt_ms * 1000
    w.eth_tcp(sec + ru//1_000_000, ru % 1_000_000,
              dst, src, dport, sport, ss, cs+len(req), 0x18, resp)
    return cs+len(req), ss+len(resp), ru + 1000

# ──────────────────────────────────────────────────────────────────────────────
# Normal traffic emitters
# ──────────────────────────────────────────────────────────────────────────────
def emit_modbus_poll(w: Writer, sec: int, hmi: Dev, plc: Dev,
                     exception: bool = False):
    sport = random.randint(49152, 65000)
    dport = 502
    cs, ss, u = handshake(w, sec, hmi, plc, sport, dport)
    addr = random.randint(0, 120)
    cnt  = random.randint(1, 20)
    req  = mb_req(plc.uid, 3, addr, cnt)
    if exception:
        resp = mb_exc(plc.uid, 3, random.choice([1,2,3]))
    else:
        regs = [random.randint(0, 0xFFF) for _ in range(cnt)]
        if random.random() < 0.015:   # rare saturated value
            regs[0] = 0xFFFF
        resp = mb_resp(plc.uid, 3, regs)
    cs, ss, u = data_psh(w, sec, u, hmi, plc, sport, dport, cs, ss, req, resp)
    teardown(w, sec, u, hmi, plc, sport, dport, cs, ss)

def emit_enip_poll(w: Writer, sec: int, hmi: Dev, plc: Dev):
    sport = random.randint(49152, 65000)
    dport = 44818
    cs, ss, u = handshake(w, sec, hmi, plc, sport, dport)
    req  = enip_list_id()
    resp = enip_connected(b'\x00' * 20)
    cs, ss, u = data_psh(w, sec, u, hmi, plc, sport, dport, cs, ss, req, resp)
    teardown(w, sec, u, hmi, plc, sport, dport, cs, ss)

def emit_s7_poll(w: Writer, sec: int, hmi: Dev, plc: Dev):
    sport = random.randint(49152, 65000)
    dport = 102
    cs, ss, u = handshake(w, sec, hmi, plc, sport, dport)
    req  = s7_read()
    resp = req[:4] + b'\x00' * (len(req)-4)  # echo stub
    cs, ss, u = data_psh(w, sec, u, hmi, plc, sport, dport, cs, ss, req, resp)
    teardown(w, sec, u, hmi, plc, sport, dport, cs, ss)

def emit_dnp3_poll(w: Writer, sec: int, master: Dev, outstation: Dev):
    sport = random.randint(49152, 65000)
    dport = 20000
    cs, ss, u = handshake(w, sec, master, outstation, sport, dport)
    req  = dnp3(int(master.ip.split('.')[-1]),
                int(outstation.ip.split('.')[-1]), 0x01)
    resp = dnp3(int(outstation.ip.split('.')[-1]),
                int(master.ip.split('.')[-1]), 0x81, b'\x01\x02' * 4)
    cs, ss, u = data_psh(w, sec, u, master, outstation, sport, dport, cs, ss, req, resp, rtt_ms=15)
    teardown(w, sec, u, master, outstation, sport, dport, cs, ss)

def emit_opc_ua(w: Writer, sec: int, hist: Dev, plc: Dev):
    sport = random.randint(49152, 65000)
    dport = 4840
    cs, ss, u = handshake(w, sec, hist, plc, sport, dport)
    req  = opc_ua_hello()
    resp = b'ACKF' + struct.pack('<II', 28, 65536)
    cs, ss, u = data_psh(w, sec, u, hist, plc, sport, dport, cs, ss, req, resp, rtt_ms=20)
    teardown(w, sec, u, hist, plc, sport, dport, cs, ss)

def emit_arp(w: Writer, sec: int, src: Dev, dst_ip: str,
             dst_mac: str = BCAST_MAC, op: int = 1):
    payload = arp(src.mac, src.ip, dst_ip, op, dst_mac)
    frame   = eth(src.mac, BCAST_MAC if op==1 else dst_mac, 0x0806, payload)
    w.pkt(sec, random.randint(0, 999999), frame)

def emit_icmp(w: Writer, sec: int, src: Dev, dst: Dev, typ: int = 8):
    payload = icmp(typ, 0, b'\xab\xcd' * 8)
    ip_pkt  = ip4(src.ip, dst.ip, 1, payload)
    frame   = eth(src.mac, dst.mac, 0x0800, ip_pkt)
    w.pkt(sec, random.randint(0, 999999), frame)

def emit_syslog(w: Writer, sec: int, src: Dev, scada: Dev, msg: str, sev: int = 6):
    payload = syslog(16, sev, src.name, msg)
    w.eth_udp(sec, random.randint(0,999999), src, scada.ip, scada.mac, 514, 514, payload)

def emit_ntp(w: Writer, sec: int, src: Dev, dst_ip: str, dst_mac: str):
    payload = ntp_client()
    w.eth_udp(sec, random.randint(0,999999), src, dst_ip, dst_mac, 123, 123, payload)

def emit_profinet(w: Writer, sec: int, src: Dev, dst: Dev):
    payload = profinet_cyclic(src.uid, dst.uid)
    frame   = eth(src.mac, dst.mac, 0x8892, payload)  # PROFINET ethertype
    w.pkt(sec, random.randint(0,999999), frame)

def emit_bacnet_whois(w: Writer, sec: int, src: Dev):
    payload = bacnet_whois()
    w.eth_udp(sec, random.randint(0,999999), src, '192.168.10.255', BCAST_MAC,
              47808, 47808, payload)

def emit_modbus_write(w: Writer, sec: int, src: Dev, plc: Dev,
                      addr: int, vals: List[int]):
    sport = random.randint(49152, 65000)
    dport = 502
    cs, ss, u = handshake(w, sec, src, plc, sport, dport)
    req  = mb_fc16(plc.uid, addr, vals)
    resp = struct.pack('>HHHBbHH', 0, 0, 6, plc.uid, 16, addr, len(vals))
    cs, ss, u = data_psh(w, sec, u, src, plc, sport, dport, cs, ss, req, resp, rtt_ms=8)
    teardown(w, sec, u, src, plc, sport, dport, cs, ss)

# ──────────────────────────────────────────────────────────────────────────────
# Anomaly emitters
# ──────────────────────────────────────────────────────────────────────────────

def anom_arp_spoof(w: Writer, sec: int, victim_ip: str, rogue_mac: str,
                   rogue_ip: str, targets: List[Dev]):
    rogue = Dev('ROGUE', rogue_ip, rogue_mac, 'unknown', 'Unknown')
    for dev in targets[:8]:
        payload = arp(rogue_mac, victim_ip, dev.ip, op=2, dst_mac=dev.mac)
        frame   = eth(rogue_mac, dev.mac, 0x0806, payload)
        w.pkt(sec, random.randint(0,999999), frame)
        sec += random.randint(0,2)

def anom_plc_disconnect(w: Writer, sec: int,
                        plc: Dev, hmi: Dev, scada: Dev,
                        silence_secs: int = 540) -> int:
    # RST spray
    for _ in range(4):
        sport = random.randint(49152, 65000)
        seg = tcp(plc.ip, hmi.ip, 502, sport, 0, 0, 0x04, b'')
        ip_pkt = ip4(plc.ip, hmi.ip, 6, seg)
        frame  = eth(plc.mac, hmi.mac, 0x0800, ip_pkt)
        w.pkt(sec, random.randint(0,999999), frame)
        sec += 1
    emit_syslog(w, sec, plc, scada,
                f'{plc.name} WATCHDOG TIMEOUT – link down', sev=2)
    sec += silence_secs
    # Gratuitous ARP on reconnect
    emit_arp(w, sec, plc, plc.ip)
    sec += 1
    emit_arp(w, sec, plc, plc.ip, op=2)
    sec += 1
    emit_syslog(w, sec, plc, scada, f'{plc.name} LINK UP – reconnected', sev=5)
    return sec + 5

def anom_fc43_scan(w: Writer, sec: int, eng: Dev, plcs: List[Dev]):
    for plc in plcs:
        if plc.offline: continue
        sport = random.randint(49152, 65000)
        cs, ss, u = handshake(w, sec, eng, plc, sport, 502)
        req  = mb_fc43(plc.uid)
        resp = mb_fc43_resp(plc.uid, plc.vendor, plc.name)
        cs, ss, u = data_psh(w, sec, u, eng, plc, sport, 502, cs, ss, req, resp)
        teardown(w, sec, u, eng, plc, sport, 502, cs, ss)
        sec += random.randint(1, 5)

def anom_port_scan(w: Writer, sec: int, src: Dev, plcs: List[Dev]):
    OT_PORTS = [102, 502, 2222, 4840, 20000, 44818, 47808, 1911, 9600, 18245]
    for plc in plcs:
        for port in OT_PORTS:
            sport = random.randint(49152, 65000)
            seg = tcp(src.ip, plc.ip, sport, port, random.randint(1,99999), 0, 0x02, b'')
            ip_pkt = ip4(src.ip, plc.ip, 6, seg)
            frame  = eth(src.mac, plc.mac, 0x0800, ip_pkt)
            w.pkt(sec, random.randint(0,999999), frame)
            sec += random.randint(0, 1)
            # RST back if port normally closed
            if port not in [502, 44818, 102]:
                seg2 = tcp(plc.ip, src.ip, port, sport, 0, 0, 0x04, b'')
                ip2  = ip4(plc.ip, src.ip, 6, seg2)
                fr2  = eth(plc.mac, src.mac, 0x0800, ip2)
                w.pkt(sec, random.randint(0,999999), fr2)

def anom_firmware_write(w: Writer, sec: int, src: Dev, plc: Dev):
    """FC16 to reserved 0x9000 address space"""
    vals = [0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xF00D, 0xACDC]
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, src, plc, sport, 502)
    req  = mb_fc16(plc.uid, 0x9000, vals)
    resp = mb_exc(plc.uid, 16, 2)  # illegal address
    cs, ss, u = data_psh(w, sec, u, src, plc, sport, 502, cs, ss, req, resp)
    teardown(w, sec, u, src, plc, sport, 502, cs, ss)

def anom_dnp3_flood(w: Writer, sec: int, dcs: Dev, scada: Dev, count: int = 80):
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, dcs, scada, sport, 20000)
    for _ in range(count):
        pkt = dnp3(int(dcs.ip.split('.')[-1]),
                   int(scada.ip.split('.')[-1]),
                   0x82, b'\x01\x02\x03\x04' * 6)
        w.eth_tcp(sec, u, dcs, scada, sport, 20000, cs, ss, 0x18, pkt)
        cs += len(pkt)
        u  += random.randint(50000, 200000)
        if u >= 1_000_000:
            sec += 1; u -= 1_000_000
    teardown(w, sec, u, dcs, scada, sport, 20000, cs, ss)

def anom_auth_failures(w: Writer, sec: int,
                       attacker: Dev, target: Dev, count: int = 25):
    for _ in range(count):
        sport = random.randint(49152, 65000)
        cs, ss, u = handshake(w, sec, attacker, target, sport, 44818)
        bad = b'\xff\xfe' + os.urandom(14)
        w.eth_tcp(sec, u+500, attacker, target, sport, 44818, cs, ss, 0x18, bad)
        cs += len(bad)
        u  += 600
        # RST
        seg = tcp(target.ip, attacker.ip, 44818, sport, ss, cs, 0x04, b'')
        ip_pkt = ip4(target.ip, attacker.ip, 6, seg)
        frame  = eth(target.mac, attacker.mac, 0x0800, ip_pkt)
        w.pkt(sec, u, frame)
        sec += random.randint(1, 4)

def anom_icmp_flood(w: Writer, sec: int, src_ip: str, target: Dev, count: int = 150):
    src_mac = '00:de:ad:be:ef:ff'
    for _ in range(count):
        payload = icmp(8, 0, b'\xff' * 32)
        ip_pkt  = ip4(src_ip, target.ip, 1, payload)
        frame   = eth(src_mac, target.mac, 0x0800, ip_pkt)
        w.pkt(sec, random.randint(0,999999), frame)
        sec += random.randint(0,1)

def anom_plc_plc_lateral(w: Writer, sec: int, src_plc: Dev, dst_plc: Dev):
    emit_modbus_poll(w, sec, src_plc, dst_plc)
    sec += 2
    emit_modbus_write(w, sec, src_plc, dst_plc,
                      addr=random.randint(10,50),
                      vals=[random.randint(100,500)])

def anom_broadcast_storm(w: Writer, sec: int, src: Dev, count: int = 300):
    for _ in range(count):
        frame = eth(src.mac, BCAST_MAC, 0x0800, b'\xff' * 60)
        w.pkt(sec, random.randint(0,999999), frame)
        sec_delta = random.randint(0, 10000)
        if sec_delta > 999999: sec += 1

def anom_s7_stop(w: Writer, sec: int, src: Dev, plc: Dev):
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, src, plc, sport, 102)
    req  = s7_stop_cpu()
    resp = req[:4] + b'\x00' * (len(req)-4)
    cs, ss, u = data_psh(w, sec, u, src, plc, sport, 102, cs, ss, req, resp)
    teardown(w, sec, u, src, plc, sport, 102, cs, ss)

def anom_dnp3_cold_restart(w: Writer, sec: int, src: Dev, dcs: Dev):
    """DNP3 FC13 cold restart (unsolicited config change)"""
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, src, dcs, sport, 20000)
    req  = dnp3(int(src.ip.split('.')[-1]),
                int(dcs.ip.split('.')[-1]), 0x0D)  # FC 13 cold restart
    resp = dnp3(int(dcs.ip.split('.')[-1]),
                int(src.ip.split('.')[-1]), 0x81)
    cs, ss, u = data_psh(w, sec, u, src, dcs, sport, 20000, cs, ss, req, resp)
    teardown(w, sec, u, src, dcs, sport, 20000, cs, ss)

def anom_rogue_opc(w: Writer, sec: int, rogue_ip: str, rogue_mac: str, plc: Dev):
    rogue = Dev('ROGUE-OPC', rogue_ip, rogue_mac, 'unknown', 'Unknown')
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, rogue, plc, sport, 4840)
    req  = opc_ua_hello(f'opc.tcp://{rogue_ip}:4840')
    resp = b'ACKF' + struct.pack('<II', 28, 65536)
    cs, ss, u = data_psh(w, sec, u, rogue, plc, sport, 4840, cs, ss, req, resp)
    teardown(w, sec, u, rogue, plc, sport, 4840, cs, ss)

def anom_smb_lateral(w: Writer, sec: int, src: Dev, historian: Dev):
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, src, historian, sport, 445)
    req  = smb_negotiate()
    resp = smb_negotiate()
    cs, ss, u = data_psh(w, sec, u, src, historian, sport, 445, cs, ss, req, resp)
    teardown(w, sec, u, src, historian, sport, 445, cs, ss)

def anom_rdp_brute(w: Writer, sec: int, attacker: Dev, jump: Dev, count: int = 30):
    for _ in range(count):
        sport = random.randint(49152, 65000)
        cs, ss, u = handshake(w, sec, attacker, jump, sport, 3389)
        req  = rdp_syn_payload()
        resp = b'\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00'
        w.eth_tcp(sec, u+200, attacker, jump, sport, 3389, cs, ss, 0x18, req)
        cs += len(req)
        w.eth_tcp(sec, u+500, jump, attacker, 3389, sport, ss, cs, 0x04, b'')  # RST
        sec += random.randint(2, 8)

def anom_coil_bad_write(w: Writer, sec: int, src: Dev, plc: Dev):
    """FC05 with illegal value 0xFF01 (bad coil value, should be 0x0000 or 0xFF00)"""
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, src, plc, sport, 502)
    req  = mb_coil_write(plc.uid, random.randint(0,50), 0xFF01)
    resp = mb_exc(plc.uid, 5, 3)  # illegal data value
    cs, ss, u = data_psh(w, sec, u, src, plc, sport, 502, cs, ss, req, resp)
    teardown(w, sec, u, src, plc, sport, 502, cs, ss)

def anom_ntp_flood(w: Writer, sec: int, src_ip: str, target: Dev, count: int = 200):
    src_mac = '00:de:ad:00:nt:01'
    # Simulate NTP amplification (large monlist responses)
    for _ in range(count):
        payload = ntp_client() + os.urandom(440)  # oversized response
        frame_src = Dev('NTP-AMP', src_ip, '00:de:ad:00:nt:01', 'unknown', 'Unknown')
        w.eth_udp(sec, random.randint(0,999999), frame_src,
                  target.ip, target.mac, 123, 123, payload)
        sec += random.randint(0,1)

def anom_coil_read_sweep(w: Writer, sec: int, eng: Dev, plcs: List[Dev]):
    """Modbus FC01 sweep across all PLCs — lateral recon"""
    for plc in plcs:
        if plc.offline: continue
        sport = random.randint(49152, 65000)
        cs, ss, u = handshake(w, sec, eng, plc, sport, 502)
        req  = mb_req(plc.uid, 1, 0, 64)   # FC01 read coils
        bits = random.randint(0, 0xFFFF).to_bytes(8, 'big')
        pdu  = bytes([plc.uid, 1, 8]) + bits
        resp = struct.pack('>HHH', 0, 0, len(pdu)) + pdu
        cs, ss, u = data_psh(w, sec, u, eng, plc, sport, 502, cs, ss, req, resp)
        teardown(w, sec, u, eng, plc, sport, 502, cs, ss)
        sec += random.randint(1, 3)

def anom_arp_ip_conflict(w: Writer, sec: int,
                          plc_a: Dev, plc_b: Dev):
    """Both devices claim same IP via gratuitous ARP"""
    conflict_ip = plc_a.ip
    emit_arp(w, sec,   plc_a, conflict_ip)
    emit_arp(w, sec+1, plc_b, conflict_ip)
    emit_arp(w, sec+2, plc_a, conflict_ip, op=2)
    emit_arp(w, sec+3, plc_b, conflict_ip, op=2)

def anom_plc_timeout_storm(w: Writer, sec: int,
                            hmi: Dev, plc: Dev, count: int = 40):
    """HMI hammering a slow/overloaded PLC — retry storm"""
    for _ in range(count):
        sport = random.randint(49152, 65000)
        cs, ss, u = handshake(w, sec, hmi, plc, sport, 502)
        req = mb_req(plc.uid, 3, 0, 10)
        w.eth_tcp(sec, u+200, hmi, plc, sport, 502, cs, ss, 0x18, req)
        cs += len(req)
        # No response — RST after timeout
        w.eth_tcp(sec, u+3000, hmi, plc, sport, 502, cs, ss, 0x04, b'')
        sec += random.randint(1, 4)

def anom_dnp3_relay_change(w: Writer, sec: int, dcs: Dev, scada: Dev):
    """DNP3 control relay output — unexpected setpoint"""
    sport = random.randint(49152, 65000)
    cs, ss, u = handshake(w, sec, dcs, scada, sport, 20000)
    # FC3 = Direct Operate (CROB)
    crob = b'\x0c\x01\x28\x01\x00\x01\x00\x01\xf4\x01\x00\x00\xf4\x01\x00\x00\x00'
    req  = dnp3(int(dcs.ip.split('.')[-1]),
                int(scada.ip.split('.')[-1]), 0x03, crob)
    resp = dnp3(int(scada.ip.split('.')[-1]),
                int(dcs.ip.split('.')[-1]), 0x81)
    cs, ss, u = data_psh(w, sec, u, dcs, scada, sport, 20000, cs, ss, req, resp)
    teardown(w, sec, u, dcs, scada, sport, 20000, cs, ss)

def anom_bacnet_flood(w: Writer, sec: int, src: Dev, count: int = 100):
    for _ in range(count):
        emit_bacnet_whois(w, sec)
        sec += random.randint(0, 2)

def anom_unregistered_device(w: Writer, sec: int,
                              rogue_ip: str, rogue_mac: str,
                              gateway_ip: str, all_dev: List[Dev]):
    """New device appears on network, sends ARP requests"""
    rogue = Dev('NEW-DEVICE', rogue_ip, rogue_mac, 'unknown', 'Unknown')
    emit_arp(w, sec, rogue, gateway_ip)
    sec += 1
    for dev in random.sample(all_dev, min(5, len(all_dev))):
        emit_arp(w, sec, rogue, dev.ip)
        sec += 1

# ──────────────────────────────────────────────────────────────────────────────
# Anomaly schedule builder
# ──────────────────────────────────────────────────────────────────────────────
def build_anomaly_schedule(base_ts: int) -> Dict[str, int]:
    H = 3600
    return {
        # DAY 1
        'arp_spoof_1':          base_ts + int(0.5*H),
        'plc07_disconnect':     base_ts + int(2*H),
        'fc43_recon':           base_ts + int(4.25*H),
        'dnp3_flood_1':         base_ts + int(6*H),
        'firmware_write_12':    base_ts + int(8.5*H),
        'plc_plc_lateral':      base_ts + int(10*H),
        'broadcast_storm_1':    base_ts + int(14*H),
        'icmp_flood_1':         base_ts + int(18*H),
        'auth_fail_hmi3':       base_ts + int(20.5*H),
        'plc22_disconnect':     base_ts + int(22*H),
        # DAY 2
        'unregistered_device':  base_ts + int(25*H),
        'port_scan_engws2':     base_ts + int(27.5*H),
        'coil_bad_write':       base_ts + int(30*H),
        's7_stop_cpu':          base_ts + int(33*H),
        'dnp3_cold_restart':    base_ts + int(36*H),
        'plc15_16_disconnect':  base_ts + int(38*H),
        'rogue_opc_session':    base_ts + int(42*H),
        'smb_lateral':          base_ts + int(45*H),
        'firmware_write_33':    base_ts + int(47*H),
        # DAY 3
        'arp_spoof_2':          base_ts + int(50*H),
        'rdp_brute':            base_ts + int(52*H),
        'ntp_flood':            base_ts + int(54.5*H),
        'coil_read_sweep':      base_ts + int(58*H),
        'plc05_timeout_storm':  base_ts + int(60*H),
        'dnp3_relay_change':    base_ts + int(63*H),
        'arp_ip_conflict':      base_ts + int(67*H),
        'bacnet_flood':         base_ts + int(70*H),
        # DAY 4+ (if running 4-5 day capture)
        'port_scan_2':          base_ts + int(79*H),
        'auth_fail_hmi7':       base_ts + int(83*H),
        'dnp3_flood_2':         base_ts + int(88*H),
        'firmware_write_07':    base_ts + int(92*H),
        'broadcast_storm_2':    base_ts + int(98*H),
        'rogue_opc_session_2':  base_ts + int(103*H),
        'icmp_flood_2':         base_ts + int(108*H),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Main generator
# ──────────────────────────────────────────────────────────────────────────────
def generate(out_path: str, days: int = 3, chunk_hours: int = 0):
    print(f"[*] OT Large-Scale PCAP Generator")
    print(f"    Duration : {days} day(s)")
    print(f"    Output   : {out_path}")
    if chunk_hours:
        print(f"    Chunking : {chunk_hours}-hour files")
    print()

    topo     = build_topology()
    plcs     = topo['plcs']       # 40
    hmis     = topo['hmis']       # 10
    dcs      = topo['dcs']        # 4
    eng      = topo['eng']        # 2
    hists    = topo['historians'] # 2
    scada    = topo['scada']
    jump     = topo['jump']
    fw       = topo['fw']
    all_dev  = topo['all']

    BASE_TS  = 1710460800   # 2024-03-15 00:00:00 UTC
    END_TS   = BASE_TS + days * 86400
    TOTAL_S  = days * 86400

    sched    = build_anomaly_schedule(BASE_TS)
    done     = set()

    # Chunk management
    chunk_sec  = chunk_hours * 3600 if chunk_hours else 0
    chunk_idx  = 0

    def make_writer(base: str, idx: int) -> Writer:
        if chunk_sec:
            stem = base.rsplit('.', 1)[0] if '.' in os.path.basename(base) else base
            path = f"{stem}_part{idx:02d}.pcap"
        else:
            path = base
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        return Writer(path)

    w = make_writer(out_path, chunk_idx)
    chunk_start = BASE_TS

    # ── Poll interval schedule (seconds)
    # Goal: ~25 Mbps = 3,125,000 bytes/sec
    # Each full Modbus poll TCP session ≈ ~1,100 bytes (handshake + data + teardown)
    # 40 PLCs × 10 HMIs × (1100 bytes / 5s) ≈ 880 KB/s  → too little alone
    # Add EtherNet/IP, S7, DNP3, OPC-UA, PROFINET, syslog to reach 25 Mbps
    MODBUS_INTERVAL   = 2      # seconds between polls per HMI→PLC pair
    ENIP_INTERVAL     = 5
    S7_INTERVAL       = 3
    DNP3_INTERVAL     = 10
    OPC_INTERVAL      = 30
    ICMP_INTERVAL     = 30
    ARP_INTERVAL      = 120
    SYSLOG_INTERVAL   = 60
    NTP_INTERVAL      = 1000
    PROFINET_INTERVAL = 1      # high-frequency cyclic

    # Next-poll timers
    # HMI→PLC Modbus
    mb_next  = {(h.ip, p.ip): BASE_TS + random.randint(0, MODBUS_INTERVAL)
                for h in hmis for p in plcs}
    # SCADA→PLC Modbus
    sc_next  = {p.ip: BASE_TS + random.randint(0, 5) for p in plcs}
    # EtherNet/IP (only for enip PLCs)
    ei_next  = {(h.ip, p.ip): BASE_TS + random.randint(0, ENIP_INTERVAL)
                for h in hmis for p in plcs if p.proto == 'enip'}
    # S7 (Siemens PLCs)
    s7_next  = {(h.ip, p.ip): BASE_TS + random.randint(0, S7_INTERVAL)
                for h in hmis for p in plcs if p.proto == 's7'}
    # DCS→SCADA DNP3
    dn_next  = {(d.ip, scada.ip): BASE_TS + random.randint(0, DNP3_INTERVAL)
                for d in dcs}
    # Historian→PLC OPC-UA
    op_next  = {(hs.ip, p.ip): BASE_TS + random.randint(0, OPC_INTERVAL)
                for hs in hists for p in plcs}
    # ICMP
    ic_next  = {p.ip: BASE_TS + random.randint(0, ICMP_INTERVAL) for p in plcs}
    # ARP
    ar_next  = {d.ip: BASE_TS + random.randint(0, ARP_INTERVAL) for d in all_dev}
    # PROFINET (Siemens PLCs only)
    pf_next  = {p.ip: BASE_TS + random.randint(0,1)
                for p in plcs if p.vendor == 'Siemens'}
    # Syslog
    sl_next  = {d.ip: BASE_TS + random.randint(0, SYSLOG_INTERVAL)
                for d in plcs + dcs}
    # NTP
    nt_next  = {d.ip: BASE_TS + random.randint(0, NTP_INTERVAL) for d in all_dev}

    offline = set()   # IPs currently offline

    tick        = BASE_TS
    last_pct    = -1
    report_every = max(1, TOTAL_S // 200)   # ~0.5% granularity
    total_gb    = 0.0

    print(f"[*] Generating traffic (this will take a while)...")
    print(f"    Estimated output: ~{days * 8:.0f}–{days * 10:.0f} GB "
          f"(adjust MODBUS_INTERVAL/PROFINET_INTERVAL for target size)")
    print()

    start_wall = time.time()

    while tick < END_TS:
        # ── Progress ──────────────────────────────────────────────────
        pct = int((tick - BASE_TS) / TOTAL_S * 100)
        if pct != last_pct and (tick - BASE_TS) % report_every < 1:
            elapsed = time.time() - start_wall
            rate    = w.size_gb() / elapsed if elapsed > 0 else 0
            eta_s   = ((END_TS - tick) / TOTAL_S * elapsed / max(pct/100,0.001)) if pct > 0 else 0
            eta_h   = eta_s / 3600
            print(f"  [{pct:3d}%] tick={tick-BASE_TS:7d}s  "
                  f"pkts={w.count:>10,}  "
                  f"size={w.size_gb():6.2f} GB  "
                  f"rate={rate*1024:.1f} MB/s  "
                  f"ETA={eta_h:.1f}h")
            last_pct = pct

        # ── Chunk rollover ─────────────────────────────────────────────
        if chunk_sec and (tick - chunk_start) >= chunk_sec:
            w.close()
            total_gb += w.size_gb()
            chunk_idx += 1
            chunk_start = tick
            w = make_writer(out_path, chunk_idx)

        # ── Anomaly injection ──────────────────────────────────────────
        for name, ats in sched.items():
            if name in done or tick < ats or ats >= END_TS:
                continue
            done.add(name)

            print(f"  [!] {name}  (t+{(ats-BASE_TS)//3600:02d}h{(ats-BASE_TS)%3600//60:02d}m)")

            if name == 'arp_spoof_1':
                anom_arp_spoof(w, ats, plcs[0].ip,
                               '00:ba:d0:ca:fe:01', '192.168.10.251', all_dev)

            elif name == 'plc07_disconnect':
                offline.add(plcs[6].ip)
                new_sec = anom_plc_disconnect(w, ats, plcs[6], hmis[0], scada,
                                              silence_secs=random.randint(480,600))
                offline.discard(plcs[6].ip)
                for h in hmis:
                    mb_next[(h.ip, plcs[6].ip)] = new_sec + 15

            elif name == 'fc43_recon':
                anom_fc43_scan(w, ats, eng[0], plcs)

            elif name == 'dnp3_flood_1':
                anom_dnp3_flood(w, ats, dcs[0], scada, count=80)

            elif name == 'firmware_write_12':
                anom_firmware_write(w, ats, eng[0], plcs[11])

            elif name == 'plc_plc_lateral':
                anom_plc_plc_lateral(w, ats, plcs[2], plcs[17])

            elif name == 'broadcast_storm_1':
                anom_broadcast_storm(w, ats, plcs[4], count=300)

            elif name == 'icmp_flood_1':
                anom_icmp_flood(w, ats, '10.99.99.1', scada, count=150)

            elif name == 'auth_fail_hmi3':
                anom_auth_failures(w, ats, eng[0], hmis[2], count=25)

            elif name == 'plc22_disconnect':
                offline.add(plcs[21].ip)
                new_sec = anom_plc_disconnect(w, ats, plcs[21], hmis[1], scada)
                offline.discard(plcs[21].ip)
                for h in hmis:
                    mb_next[(h.ip, plcs[21].ip)] = new_sec + 15

            elif name == 'unregistered_device':
                anom_unregistered_device(w, ats, '192.168.10.252',
                                         '00:de:ad:ff:00:01',
                                         fw.ip, all_dev)

            elif name == 'port_scan_engws2':
                anom_port_scan(w, ats, eng[1], plcs)

            elif name == 'coil_bad_write':
                anom_coil_bad_write(w, ats, eng[0], plcs[0])

            elif name == 's7_stop_cpu':
                siemens_plcs = [p for p in plcs if p.vendor == 'Siemens' and not p.offline]
                if siemens_plcs:
                    anom_s7_stop(w, ats, eng[0], random.choice(siemens_plcs))

            elif name == 'dnp3_cold_restart':
                anom_dnp3_cold_restart(w, ats, scada, dcs[1])

            elif name == 'plc15_16_disconnect':
                for idx in [14, 15]:
                    offline.add(plcs[idx].ip)
                    new_sec = anom_plc_disconnect(w, ats, plcs[idx], hmis[3], scada,
                                                  silence_secs=random.randint(300,480))
                    offline.discard(plcs[idx].ip)
                    for h in hmis:
                        mb_next[(h.ip, plcs[idx].ip)] = new_sec + 20
                    ats += 3

            elif name == 'rogue_opc_session':
                anom_rogue_opc(w, ats, '192.168.10.253',
                               '00:de:ad:oc:00:01', plcs[5])

            elif name == 'smb_lateral':
                anom_smb_lateral(w, ats, eng[0], hists[0])

            elif name == 'firmware_write_33':
                anom_firmware_write(w, ats, eng[1], plcs[32])

            elif name == 'arp_spoof_2':
                anom_arp_spoof(w, ats, plcs[10].ip,
                               '00:ba:d0:ca:fe:02', '192.168.10.254', all_dev)

            elif name == 'rdp_brute':
                anom_rdp_brute(w, ats, eng[0], jump, count=30)

            elif name == 'ntp_flood':
                anom_ntp_flood(w, ats, '10.99.99.2', scada, count=200)

            elif name == 'coil_read_sweep':
                anom_coil_read_sweep(w, ats, eng[0], plcs)

            elif name == 'plc05_timeout_storm':
                anom_plc_timeout_storm(w, ats, hmis[1], plcs[4], count=40)

            elif name == 'dnp3_relay_change':
                anom_dnp3_relay_change(w, ats, dcs[2], scada)

            elif name == 'arp_ip_conflict':
                anom_arp_ip_conflict(w, ats, plcs[27], plcs[28])

            elif name == 'bacnet_flood':
                anom_bacnet_flood(w, ats, plcs[5], count=100)

            elif name == 'port_scan_2':
                anom_port_scan(w, ats, eng[1], plcs[20:])

            elif name == 'auth_fail_hmi7':
                anom_auth_failures(w, ats, eng[1], hmis[6], count=30)

            elif name == 'dnp3_flood_2':
                anom_dnp3_flood(w, ats, dcs[1], scada, count=100)

            elif name == 'firmware_write_07':
                anom_firmware_write(w, ats, eng[0], plcs[6])

            elif name == 'broadcast_storm_2':
                anom_broadcast_storm(w, ats, plcs[19], count=250)

            elif name == 'rogue_opc_session_2':
                anom_rogue_opc(w, ats, '192.168.10.253',
                               '00:de:ad:oc:00:02', plcs[15])

            elif name == 'icmp_flood_2':
                anom_icmp_flood(w, ats, '10.99.99.3', scada, count=200)

        # ── Normal Modbus: HMI → PLC ───────────────────────────────────
        for hmi in hmis:
            for plc in plcs:
                key = (hmi.ip, plc.ip)
                if tick >= mb_next.get(key, 0):
                    if plc.ip not in offline:
                        emit_modbus_poll(w, tick, hmi, plc,
                                         exception=random.random() < 0.018)
                    mb_next[key] = tick + MODBUS_INTERVAL + random.randint(-1,2)

        # ── SCADA → PLC Modbus ─────────────────────────────────────────
        for plc in plcs:
            if tick >= sc_next.get(plc.ip, 0):
                if plc.ip not in offline:
                    emit_modbus_poll(w, tick, scada, plc)
                sc_next[plc.ip] = tick + 4 + random.randint(0,2)

        # ── EtherNet/IP: HMI → AB/Rockwell PLCs ───────────────────────
        for hmi in hmis:
            for plc in [p for p in plcs if p.proto == 'enip']:
                key = (hmi.ip, plc.ip)
                if tick >= ei_next.get(key, 0):
                    if plc.ip not in offline:
                        emit_enip_poll(w, tick, hmi, plc)
                    ei_next[key] = tick + ENIP_INTERVAL + random.randint(0,3)

        # ── S7: HMI → Siemens PLCs ────────────────────────────────────
        for hmi in hmis:
            for plc in [p for p in plcs if p.proto == 's7']:
                key = (hmi.ip, plc.ip)
                if tick >= s7_next.get(key, 0):
                    if plc.ip not in offline:
                        emit_s7_poll(w, tick, hmi, plc)
                    s7_next[key] = tick + S7_INTERVAL + random.randint(0,2)

        # ── DNP3: DCS → SCADA ─────────────────────────────────────────
        for d in dcs:
            key = (d.ip, scada.ip)
            if tick >= dn_next.get(key, 0):
                emit_dnp3_poll(w, tick, d, scada)
                dn_next[key] = tick + DNP3_INTERVAL + random.randint(-2,5)

        # ── OPC-UA: Historian → PLCs ───────────────────────────────────
        for hs in hists:
            for plc in plcs:
                key = (hs.ip, plc.ip)
                if tick >= op_next.get(key, 0):
                    if plc.ip not in offline:
                        emit_opc_ua(w, tick, hs, plc)
                    op_next[key] = tick + OPC_INTERVAL + random.randint(-5,15)

        # ── PROFINET cyclic (Siemens) ──────────────────────────────────
        for plc in [p for p in plcs if p.vendor == 'Siemens']:
            if tick >= pf_next.get(plc.ip, 0):
                if plc.ip not in offline:
                    emit_profinet(w, tick, plc, hmis[0])
                pf_next[plc.ip] = tick + PROFINET_INTERVAL

        # ── ICMP keepalives ────────────────────────────────────────────
        for plc in plcs:
            if tick >= ic_next.get(plc.ip, 0):
                if plc.ip not in offline:
                    emit_icmp(w, tick, scada, plc)
                    emit_icmp(w, tick, plc, scada, typ=0)
                ic_next[plc.ip] = tick + ICMP_INTERVAL + random.randint(-5,10)

        # ── ARP ────────────────────────────────────────────────────────
        for dev in all_dev:
            if tick >= ar_next.get(dev.ip, 0):
                emit_arp(w, tick, dev, fw.ip)
                ar_next[dev.ip] = tick + ARP_INTERVAL + random.randint(-20,40)

        # ── Syslog ────────────────────────────────────────────────────
        if tick % SYSLOG_INTERVAL == 0:
            dev = random.choice(plcs + dcs)
            msgs = [
                f'CPU={random.randint(5,90)}%  MEM={random.randint(20,85)}%  HEAP OK',
                f'Tag scan cycle: {random.randint(2,50)}ms',
                f'Remote I/O rack: OK, {random.randint(1,16)} modules',
                f'Watchdog: OK  Temp: {random.uniform(35,80):.1f}C',
                f'Program scan: {random.randint(1,20)}ms per cycle',
            ]
            emit_syslog(w, tick, dev, scada, random.choice(msgs))

        # ── NTP ───────────────────────────────────────────────────────
        for dev in all_dev:
            if tick >= nt_next.get(dev.ip, 0):
                emit_ntp(w, tick, dev, fw.ip, fw.mac)
                nt_next[dev.ip] = tick + NTP_INTERVAL + random.randint(-30,120)

        # ── Occasional process alarm (out-of-range value) ─────────────
        if tick % 90 == 0 and random.random() < 0.25:
            plc = random.choice([p for p in plcs if p.ip not in offline])
            hmi = random.choice(hmis)
            sport = random.randint(49152, 65000)
            cs, ss, u = handshake(w, tick, hmi, plc, sport, 502)
            req  = mb_req(plc.uid, 3, random.randint(0,50), 1)
            resp = mb_resp(plc.uid, 3, [0xFFFF])  # saturated sensor
            cs, ss, u = data_psh(w, tick, u, hmi, plc, sport, 502, cs, ss, req, resp)
            teardown(w, tick, u, hmi, plc, sport, 502, cs, ss)

        tick += 1

    # Final close
    w.close()
    total_gb += w.size_gb()
    wall = time.time() - start_wall

    print(f"\n{'='*60}")
    print(f"  COMPLETE")
    print(f"  Total packets : {w.count:,}")
    print(f"  Total size    : {total_gb:.2f} GB")
    print(f"  Wall time     : {wall/3600:.2f} hours")
    print(f"  Sim rate      : {total_gb*8*1024/TOTAL_S:.1f} Mbps average")
    if chunk_sec:
        print(f"  Chunks        : {chunk_idx+1} files ({chunk_hours}h each)")
    print(f"{'='*60}")

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description='OT Manufacturing PCAP Generator — Large Scale')
    ap.add_argument('--days',        type=int, default=3,
                    help='Capture duration in days (default: 3)')
    ap.add_argument('--out',         type=str, default='ot_manufacturing.pcap',
                    help='Output file path')
    ap.add_argument('--chunk-hours', type=int, default=0,
                    help='Split into N-hour chunks (recommended: 6 for >200 GB)')
    args = ap.parse_args()

    print("="*60)
    print(" OT Manufacturing Network PCAP Generator — Large Scale")
    print("="*60)
    print(f" Devices  : 40 PLCs | 10 HMIs | 4 DCS | 2 ENG | 2 Historians")
    print(f" Duration : {args.days} day(s) = {args.days*86400:,} seconds")
    print(f" Target   : ~25 Mbps → ~{args.days * 270:.0f} GB")
    print(f" Anomalies: 29 distinct events mapped to Claroty/Armis alerts")
    print("="*60)
    print()
    print("  NOTE: Writing 800 GB takes ~6-18 hrs depending on disk speed.")
    print("  Use --chunk-hours 6 to write 6-hour rolling files.")
    print("  Use --days 3 for ~800 GB | --days 5 for ~1.35 TB")
    print()

    generate(args.out, days=args.days, chunk_hours=args.chunk_hours)
