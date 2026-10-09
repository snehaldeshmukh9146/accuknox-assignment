#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct
import os
import signal
import sys
import time

CGROUP_ROOT = "/sys/fs/cgroup/unified"
CGROUP_NAME = "accuknox_demo"
CGROUP_PATH = os.path.join(CGROUP_ROOT, CGROUP_NAME)
ALLOWED_PORT = 4040

program = r"""
#include <uapi/linux/bpf.h>
#include <linux/ip.h>

struct tcp_header {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

int allow_only_4040(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct tcp_header tcp;
    int ret;

    /* cgroup_skb sees the IP packet, not an Ethernet frame */
    ret = bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip));
    if (ret < 0)
        return 1;

    if (ip.version != 4)
        return 1;

    if (ip.protocol != 6)
        return 1;

    __u32 ip_header_len = ip.ihl * 4;

    if (ip_header_len < 20)
        return 1;

    ret = bpf_skb_load_bytes(
        skb,
        ip_header_len,
        &tcp,
        sizeof(tcp)
    );

    if (ret < 0)
        return 1;

    if (bpf_ntohs(tcp.dest) == 4040)
        return 1;

    return 0;
}
"""

if not os.path.isdir(CGROUP_ROOT):
    print("ERROR: cgroup v2 was not found:")
    print(CGROUP_ROOT)
    sys.exit(1)

print("Creating cgroup...")

try:
    os.mkdir(CGROUP_PATH)
    print("Created:", CGROUP_PATH)
except FileExistsError:
    print("Cgroup already exists:", CGROUP_PATH)

print("Compiling eBPF program...")

try:
    b = BPF(text=program)
except Exception:
    print("")
    print("eBPF compilation/loading failed.")
    print("")
    print("The cgroup directory was created but the")
    print("program was NOT attached.")
    print("")
    raise

print("Loading eBPF cgroup program...")

# BPF_PROG_TYPE_CGROUP_SKB
CGROUP_SKB_PROG_TYPE = 8

fn = b.load_func(
    "allow_only_4040",
    CGROUP_SKB_PROG_TYPE
)

print("Opening cgroup...")

cgroup_fd = os.open(
    CGROUP_PATH,
    os.O_RDONLY
)

libc = ct.CDLL(
    "libc.so.6",
    use_errno=True
)

# x86_64 Linux
SYS_BPF = 321

BPF_PROG_ATTACH = 8
BPF_PROG_DETACH = 9

# BPF_CGROUP_INET_EGRESS
BPF_CGROUP_INET_EGRESS = 1


class BpfProgAttachAttr(ct.Structure):
    _fields_ = [
        ("target_fd", ct.c_uint32),
        ("attach_bpf_fd", ct.c_uint32),
        ("attach_type", ct.c_uint32),
        ("attach_flags", ct.c_uint32),
        ("replace_bpf_fd", ct.c_uint32),
    ]


attr = BpfProgAttachAttr()

attr.target_fd = cgroup_fd
attr.attach_bpf_fd = fn.fd
attr.attach_type = BPF_CGROUP_INET_EGRESS
attr.attach_flags = 0
attr.replace_bpf_fd = 0


result = libc.syscall(
    SYS_BPF,
    BPF_PROG_ATTACH,
    ct.byref(attr),
    ct.sizeof(attr)
)

if result != 0:
    error_number = ct.get_errno()

    os.close(cgroup_fd)

    print("")
    print(
        "ERROR: BPF_PROG_ATTACH failed:",
        os.strerror(error_number)
    )
    print("")

    sys.exit(1)


print("")
print("==============================================")
print("Problem 2: Process TCP Port Filter")
print("==============================================")
print("")
print("Controlled cgroup:")
print(" ", CGROUP_PATH)
print("")
print("Allowed TCP destination port:", ALLOWED_PORT)
print("")
print("Policy:")
print("  TCP 4040        -> ALLOW")
print("  Other TCP ports -> DROP")
print("")
print("eBPF cgroup egress filter is running.")
print("")
print("IMPORTANT:")
print("Put the target process PID into this cgroup")
print("before testing.")
print("")
print("Press Ctrl+C to stop.")
print("==============================================")
print("")


def cleanup(signum, frame):

    print("")
    print("Removing eBPF program...")

    try:

        detach_attr = BpfProgAttachAttr()

        detach_attr.target_fd = cgroup_fd
        detach_attr.attach_bpf_fd = fn.fd
        detach_attr.attach_type = BPF_CGROUP_INET_EGRESS
        detach_attr.attach_flags = 0
        detach_attr.replace_bpf_fd = 0

        result2 = libc.syscall(
            SYS_BPF,
            BPF_PROG_DETACH,
            ct.byref(detach_attr),
            ct.sizeof(detach_attr)
        )

        if result2 == 0:
            print("eBPF program detached.")
        else:
            error_number = ct.get_errno()
            print(
                "Detach warning:",
                os.strerror(error_number)
            )

    except Exception as e:
        print("Detach warning:", e)

    try:
        os.close(cgroup_fd)
    except:
        pass

    try:
        os.rmdir(CGROUP_PATH)
        print("Cgroup removed.")
    except Exception as e:
        print(
            "Cgroup cleanup warning:",
            e
        )

    sys.exit(0)


signal.signal(
    signal.SIGINT,
    cleanup
)

signal.signal(
    signal.SIGTERM,
    cleanup
)


while True:
    time.sleep(1)
