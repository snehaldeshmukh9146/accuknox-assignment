from bcc import BPF
import ctypes as ct
import signal
import sys

# Network interface
DEVICE = "ens33"

# Read TCP port from userspace command line.
# Example:
# sudo python3 ~/problem1.py 4040
#
# If no port is provided, 4040 is used.
try:
    BLOCK_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4040
except ValueError:
    raise SystemExit("ERROR: Port must be a number.")

if not 1 <= BLOCK_PORT <= 65535:
    raise SystemExit("ERROR: Port must be between 1 and 65535.")


# ---------------------------------------------------------
# eBPF / XDP program
# ---------------------------------------------------------

program = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


/*
 * Minimal TCP header definition.
 *
 * We define this ourselves instead of including linux/tcp.h
 * because the old Ubuntu 18.04/BCC environment can have
 * compatibility problems with that header.
 */
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


/*
 * BPF array containing the TCP port configured by userspace.
 *
 * Key:
 *   0
 *
 * Value:
 *   TCP port number
 */
BPF_ARRAY(block_port, u16, 1);


/*
 * XDP packet processing function.
 */
int drop_tcp_port(struct xdp_md *ctx)
{
    /*
     * Get packet start and end.
     */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;


    /*
     * -----------------------------------------
     * Ethernet header
     * -----------------------------------------
     */
    struct ethhdr *eth = data;

    /*
     * Always check packet boundaries before
     * accessing packet data.
     */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;


    /*
     * Only process IPv4 packets.
     *
     * ETH_P_IP = IPv4.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;


    /*
     * -----------------------------------------
     * IPv4 header
     * -----------------------------------------
     */
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;



    /*
     * IP protocol 6 = TCP.
     *
     * If this isn't TCP, allow the packet.
     */
    if (ip->protocol != 6)
        return XDP_PASS;


    /*
     * IPv4 header length.
     *
     * ihl is measured in 32-bit words,
     * so multiply by 4 to get bytes.
     */
    __u32 ip_header_len = ip->ihl * 4;

    if (ip_header_len < 20)
        return XDP_PASS;


    /*
     * -----------------------------------------
     * TCP header
     * -----------------------------------------
     */
    struct tcp_header *tcp =
        (void *)ip + ip_header_len;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;


    /*
     * Look up the blocked TCP port from
     * the BPF map.
     */
    __u32 key = 0;

    __u16 *blocked_port = block_port.lookup(&key);

    /*
     * If userspace has not configured a port,
     * allow the packet.
     */
    if (blocked_port == 0)
        return XDP_PASS;


    /*
     * TCP destination port is stored in
     * network byte order.
     *
     * Convert it to host byte order before
     * comparing it with our configured port.
     */
    if (bpf_ntohs(tcp->dest) == *blocked_port)
    {
        /*
         * Destination port matches the
         * configured blocked port.
         *
         * DROP the packet.
         */
        return XDP_DROP;
    }


    /*
     * All other packets are allowed.
     */
    return XDP_PASS;
}
"""


# ---------------------------------------------------------
# Compile eBPF program
# ---------------------------------------------------------

print("Compiling eBPF program...")

b = BPF(text=program)


# ---------------------------------------------------------
# Load XDP function
# ---------------------------------------------------------

print("Loading eBPF program...")

fn = b.load_func("drop_tcp_port", BPF.XDP)


# ---------------------------------------------------------
# Attach XDP program
# ---------------------------------------------------------
#
# BCC 0.5.0 does not expose:
#
#     BPF.XDP_FLAGS_SKB_MODE
#
# The numeric value 2 means XDP generic/SKB mode.
#
# This is useful for VMware/virtual interfaces such
# as ens33.
# ---------------------------------------------------------

flags = 2

print("Attaching to interface:", DEVICE)

b.attach_xdp(DEVICE, fn, flags)


# ---------------------------------------------------------
# Configure blocked port from userspace
# ---------------------------------------------------------

port_map = b.get_table("block_port")

key = ct.c_uint(0)
value = ct.c_ushort(BLOCK_PORT)

port_map[key] = value


# ---------------------------------------------------------
# Display status
# ---------------------------------------------------------

print("")
print("==========================================")
print("Problem 1: TCP Port Blocker")
print("==========================================")
print("Interface       :", DEVICE)
print("Blocked TCP port:", BLOCK_PORT)
print("")
print("TCP traffic to the configured port is DROP.")
print("Other traffic is PASS.")
print("")
print("Port configured from userspace.")
print("BPF map: block_port")
print("")
print("eBPF program is running.")
print("Press Ctrl+C to stop.")
print("==========================================")


# ---------------------------------------------------------
# Cleanup
# ---------------------------------------------------------

def cleanup(signum, frame):

    print("\nRemoving eBPF program...")

    try:
        b.remove_xdp(DEVICE, flags)
        print("eBPF program removed.")
    except Exception as e:
        print("Cleanup warning:", e)

    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ---------------------------------------------------------
# Keep program running
# ---------------------------------------------------------

while True:
    signal.pause()

