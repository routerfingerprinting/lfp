#!/usr/bin/env python3
import ndjson
import sys

MAX_PACKETS = 9
SHARED_COUNTERS = ['i1', 'i', 'ix']
IPID_THRESHOLD = 1300

scamper_json_file = sys.argv[1]

sig_vendor = {}
with open("signatures.csv") as f:
    for l in f:
        line = l.strip().split(",")
        vendor = line[-1]
        sig = line[:-1]
        sig_vendor[vendor] = sig

def get_vendor(dictionary, value):
    keys = [key for key, val in dictionary.items() if val == value]
    if len(keys) > 0:
        return keys
    else:
        return "unknown"


def get_ttl(ttl):
    if ttl < 32:
        return 32
    elif ttl < 64:
        return 64
    elif ttl < 128:
        return 128
    else:
        return 255


def test_counter(ipid_sample):
    return all(x < y or (y - x) % 65536 < IPID_THRESHOLD for x, y in zip(ipid_sample, ipid_sample[1:]))


def test_ipid_seq(L):

    if len(set(L)) == 1:
        if L[0] == 0:
            return "sz"
        else:
            return "snz"

    if len(set(L)) < len(L):
        return "dup"

    ipid_diff = [(L[i + 1] - L[i]) % 65536 for i in range(len(L) - 1)]

    if len(set(ipid_diff)) == 1:
        if len(L) == 2:
            if ipid_diff[0] == 1:
                return 'i1'
            elif sum(ipid_diff) / len(ipid_diff) < IPID_THRESHOLD:
                return 'i'
            else:
                return 'r'
        if ipid_diff[0] == 1:
            return "i1"
        else:
            return "i"
    elif sum(ipid_diff) / len(ipid_diff) <= IPID_THRESHOLD:
        return "i"
    elif sum(ipid_diff) / len(ipid_diff) > IPID_THRESHOLD:
        return 'r'
    else:
        return "u"


def size_per_proto(reply_size):
    size_icmp_echo = [reply_size[i] for i in icmp]
    size_tcp_ack = [reply_size[i] for i in tcp]
    size_udp = [reply_size[i] for i in udp]
    size = [size_icmp_echo[0], size_tcp_ack[0], size_udp[0]]
    size_sig = [str(item) for item in size]
    return size_sig


def ttl_per_proto(iTTLs):
    iTTL_icmp_echo = [iTTLs[i] for i in icmp]
    iTTL_tcp_ack = [iTTLs[i] for i in tcp]
    iTTL_udp = [iTTLs[i] for i in udp]
    ittl = [iTTL_udp[0], iTTL_icmp_echo[0], iTTL_tcp_ack[0]]
    ittl_sig = [str(item) for item in ittl]
    return ittl_sig


def get_ipid_lists(ipids_list):
    tcp_list = [ipids_list[i] for i in tcp]
    udp_list = [ipids_list[i] for i in udp]
    icmp_list = [ipids_list[i] if ipids_list[i]
                 != 'echo' else "echo" for i in icmp]
    tcp_and_udp_list = [ipids_list[i] for i in tcp_udp]
    return tcp_list, udp_list, icmp_list, tcp_and_udp_list


def process_ipids(ipids_list):
    tcp_ipid = [ipids_list[i] for i in tcp]
    udp_ipid = [ipids_list[i] for i in udp]
    icmp_echo_ipid = [ipids_list[i] if ipids_list[i]
                      != 'echo' else "echo" for i in icmp]
    tcp_and_udp_list = [ipids_list[i] for i in tcp_udp]

    tcp_ipid_counter = test_ipid_seq(tcp_ipid)
    udp_ipid_counter = test_ipid_seq(udp_ipid)

    if tcp_ipid_counter in SHARED_COUNTERS and udp_ipid_counter in SHARED_COUNTERS:
        tcp_udp_counter_share = test_counter(tcp_and_udp_list)
    else:
        tcp_udp_counter_share = False
    if 'echo' in icmp_echo_ipid:
        icmp_ipid_echo = True
        icmp_ipid_counter = "echo"
        udp_icmp_counter_share = False
        tcp_icmp_counter_share = False
        tcp_udp_icmp_counter_share = False
    else:
        icmp_ipid_echo = False
        icmp_ipid_counter = test_ipid_seq(icmp_echo_ipid)
        if icmp_ipid_counter in SHARED_COUNTERS:

            icmp_udp = udp_ipid
            icmp_udp.insert(0, icmp_echo_ipid[0])
            icmp_udp.insert(6, icmp_echo_ipid[1])
            udp_icmp_counter_share = test_counter(icmp_udp)

            icmp_tcp = tcp_ipid
            icmp_tcp.insert(0, icmp_echo_ipid[0])
            icmp_tcp.insert(5, icmp_echo_ipid[1])
            tcp_icmp_counter_share = True
        else:
            udp_icmp_counter_share = False
            tcp_icmp_counter_share = False

    if udp_icmp_counter_share and tcp_icmp_counter_share and tcp_udp_counter_share:
        tcp_udp_icmp_counter_share = test_counter(ipids_list)
    else:
        tcp_udp_icmp_counter_share = False

    ipid_features = [icmp_ipid_echo, icmp_ipid_counter, tcp_ipid_counter, udp_ipid_counter,
                     tcp_udp_icmp_counter_share, tcp_icmp_counter_share, udp_icmp_counter_share, tcp_udp_counter_share]
    string_list = [str(item) for item in ipid_features]
    return string_list


def process_response(response):
    if not response:
        return 'x', 'x', 'x', 'x'

    src_ip = response.get('from', 'x')
    reply_ipid = response['reply_ipid']
    probe_ipid = response['probe_ipid']
    reply_ttl = response['reply_ttl']
    reply_size = response['reply_size']

    if reply_ipid == probe_ipid:
        ipid_value = 'echo'
    else:
        ipid_value = reply_ipid
    ittl = get_ttl(reply_ttl)

    return src_ip, ipid_value, ittl, reply_size


with open(scamper_json_file, "r") as f:
    data = ndjson.load(f)


# scamper probe-method indices
icmp = [0, 3, 6]
tcp = [1, 4, 7]
udp = [2, 5, 8] # ICMP port unreach 
tcp_udp = [1, 2, 4, 5, 7, 8]


dst_ip = ""
ipid = []
iTTLs = []
src_ips = []
p_counter = 0
reply_size = []
reply_proto = []

for line in data:
    if line["type"] != "ping":
        continue
    else:
        dst = line["dst"]
        if dst != dst_ip:
            dst_ip = dst

        response = line['responses'][0] if line['responses'] else None
        src_ip, ipid_value, ttl_value, size_value = process_response(response)
        src_ips.append(src_ip)
        ipid.append(ipid_value)
        iTTLs.append(ttl_value)
        reply_size.append(size_value)
        p_counter += 1

    if p_counter == MAX_PACKETS:
        if 'x' in ipid:
            print(dst_ip, "unknown", "missing one or more responses", sep="|")
        else:
            tcp_list, udp_list, icmp_list, tcp_and_udp_list = get_ipid_lists(
                ipid)
            if 'echo' not in udp_list and 'echo' not in tcp_list:
                signature = process_ipids(
                    ipid) + ttl_per_proto(iTTLs) + size_per_proto(reply_size)
                print(dst_ip, get_vendor(sig_vendor, signature),
                      ','.join(map(str, signature)), sep="|")
            else:
                pass
                print(dst_ip, 'unknown', sep="|")

        ipid = []
        iTTLs = []
        src_ips = []
        p_counter = 0
        reply_size = []
        dst_ip = ""
