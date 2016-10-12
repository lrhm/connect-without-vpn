#!/usr/bin/python2.7

import argparse
import sys
import os, time


def init_parser():
    parser = argparse.ArgumentParser(description="Routing from ip list directly, not from tunnel")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument("--interface", nargs='?', dest="interface",
                        help="your desired interface that ip/masks should route in",
                        default="enp6s0")
    parser.add_argument('-i', help="input file, each line should consist of ip/netmask , lines with # will be ignored" \
                        , nargs='?', type=argparse.FileType('r'), dest="i")
    parser.add_argument("-gw", help="default gateway of your interface", nargs="?", dest="gw")
    return parser.parse_args(sys.argv[1:])


pars = init_parser()
print pars
content = pars.i.readlines()

for line in content:
    if line[0] is "#":
        continue
    ip = line.split("/")[0]
    mask = line.split("/")[1][:-1]
    cmd = "route add -net {} netmask {} gw {} dev {}".format(ip, mask, pars.gw, pars.interface)
    print(cmd)
    os.system(cmd)
