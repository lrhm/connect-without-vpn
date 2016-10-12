import fcntl
import os
import socket
import argparse
from struct import *


def init_parser():
    parser = argparse.ArgumentParser(
        description="Self learning from sniffing packets to know its censored or not. \
        if its censored then it will be routed through tunnel")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument("--interface", nargs=1, dest="interface",
                        help="your default interface which accesses censored internet",
                        default="enp6s0")
    parser.add_argument('--tun', help="your tunnel interface"
                        , nargs='?', dest="tunnel")
    parser.add_argument("-udp", help="if should sniff and route udp packets then pass True",
                        nargs="?", dest="use_udp", default=False, const=True, type=bool)
    parser.add_argument("-d", help="for debug purposes", default=False, const=True, type=bool, dest="debug")
    return parser.parse_args(sys.argv[1:])


pars = init_parser()


def set_default_route(interface, tunnel, debug):
    global pars
    cmd = "route del default"
    cmd_default = "route add default dev {}".format(interface)
    cmd_dns_route = "route add -net 8.8.8.8 netmask 255.255.255.255 dev {}".format(tunnel)
    os.system(cmd)
    os.system(cmd_default)
    os.system(cmd_dns_route)
    if debug:
        print cmd
        print cmd_default
        print cmd_dns_route


def get_ip_address(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        pack('256s', interface[:15])
    )[20:24])


def add_route(tunnel, ip, debug):
    while ip[-1] != '.':
        ip = ip[:-1]
    ip += "0"
    os.system("route add -net {} netmask 255.255.255.0 dev {}".format(ip, tunnel))
    if debug:
        print("route add -net {} netmask 255.255.255.0 dev {}".format(ip, tunnel))


def main(use_udp, tun, interface, debug):
    set_default_route(interface, tun, debug)

    time_map = {}
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    local_ip = get_ip_address()

    # receive a packet
    while True:
        packet = s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        # Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            if debug:
                print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                    ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(
                    s_addr) + ' Destination Address : ' + str(d_addr)

            # TCP protocol
            if protocol == 6:

                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                # now unpack them :)
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                h_size = eth_length + iph_length + tcph_length
                data = packet[h_size:]

                # this approach doesnt work well. should find a better one
                # if s_addr == local_ip:
                #     if d_addr not in time_map:
                #         time_map[d_addr] = 0
                #     if time_map[d_addr] != -1:
                #         time_map[d_addr] += 1
                #         if time_map[d_addr] == 20:
                #             add_route(tun, d_addr)
                if debug:
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(
                        dest_port) + ' Sequence Number : ' + str(
                        sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(
                        tcph_length)

                    print data

                    print '-----------------------------------------------------'
                if d_addr == local_ip:
                    if "403 Forbidden" in data:
                        add_route(tun, s_addr)
                    time_map[d_addr] = -1


            # UDP packets
            elif protocol == 17 and use_udp:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # now unpack them :)
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                if debug:
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
                        length) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]
                if debug:
                    print data
                    print '--------------------------------------------------------'


main(pars.use_udp, pars.tunnel, pars.interface, pars.debug)
