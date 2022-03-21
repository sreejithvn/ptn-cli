#!/usr/bin python3

import telnetlib
import time
import re
import argparse

DEFAULT_IP = "10.10.10.10"
username = "username"
password = "password"

port = 23
connection_timeout = 5
reading_timeout = 5
sleep = 1
config_sleep = 4

def argument_parser():
    parser = argparse.ArgumentParser(prog="ptn", description="CLI for monitoring CPAN")
    parser.add_argument("node_ip", default=[DEFAULT_IP], nargs="*", help="IP address of node")
    parser.add_argument("-a", "--alarm", action="store_true", help="display current alarms of node")
    parser.add_argument("-i", "--interface", nargs="+", metavar="", help="interface as eg: 2.1 3.1 ...")
    parser.add_argument("-c", "--config", action="store_true", help="configuration of the interface")
    parser.add_argument("-p", "--performance", action="store_true", help="current and cumulative performance of the interface")
    parser.add_argument("-s", "--system", action="store_true", help="system cpu memory utilisation")
    parser.add_argument("-v", "--version", action="store_true", help="system version compile time")
    return parser.parse_args()

def formatter(y):
    x = y.strip(",:;/+-.()[]}{<>''")
    if not x:
        return x
    if x[0] == "l":
        return x[0] + "ag " + x[-1]
    if x[0] != 0:
        x = "0/" + x[0] + "/0/" + x[2:]
    return x

def ip_formatter(ip_list):
    new_list=[]
    for el in ip_list:
        ip = el.strip(",:;/+-.()[]}{<>''")
        if ",:;/+-.()[]}{<>''" in ip:
            continue
        if not ip:
            continue
        new_list.append(ip)
    return new_list

def teng_check(x):
    return x[2] in "146"

def bandwidth(port, line):
    if teng_check(port):
        util = float(line.split(":")[-1])
        bw = util * 100
    else:
        util = float(line.split()[3])
        bw = util * 10
    return bw

def print_output(tel_out):
    output = tel_out.decode('ascii').split("\n")
    for line in output:
        if line != "\r":
            if "650" not in line:
                if ">" not in line:
                    if "....." not in line:
                        if "sho" not in line:
                            if "ems" not in line:
                                print(line)

args = argument_parser()
print(args.node_ip)
ip_list = ip_formatter(args.node_ip)
print(ip_list)

for ip in ip_list:
    try:
        telnet = telnetlib.Telnet(ip, port, connection_timeout)
        telnet.read_until(b"Username: ", reading_timeout)
        telnet.write(username.encode('ascii') + b"\n")
        telnet.read_until(b"Password:", reading_timeout)
        telnet.write(password.encode('ascii') + b"\n")
        print("Logged In Node: {}".format(ip))

        if args.interface:
            for port in args.interface:
                formatted_port = formatter(port.lower())
                if not formatted_port:
                    continue
                if not args.performance:
                    if teng_check(formatted_port):
                        telnet.write(b"sho inter ten " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(sleep)
                        print("\nINTERFACE TENG {}".format(port))
                        output = telnet.read_very_eager().decode('ascii').split("\n")
                        for line in output:
                            if "Power" in line:
                                print(line.strip())
                            if "util" in line:
                                bw = bandwidth(formatted_port, line)
                                if "Input" in line:
                                    print("Input bandwidth: {:6.0f} Mbps".format(bw))
                                else:
                                    print("Output bandwidth: {:5.0f} Mbps".format(bw))
                            if "error" in line:
                                print(line)
                            if "warn" in line:
                                print(line)
                    elif formatted_port[0] == "l":
                        telnet.write(b"sho " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(sleep)
                        print("\n{} MEMBER PORTS and LACP STATUS".format(formatted_port.upper()))
                        print_output(telnet.read_very_eager())
                        telnet.write(b"sho lacp count " + formatted_port.encode('ascii') + b"\n")
                        print("\n")
                        time.sleep(sleep)
                        print_output(telnet.read_very_eager())
                    else:
                        telnet.write(b"sho performance slot " + formatted_port[2].encode('ascii') + b" filter " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(sleep)
                        print("\nINTERFACE {}".format(port))
                        output = telnet.read_very_eager().decode('ascii').split("\n")
                        for line in output:
                            if "BW" in line:
                                bw = bandwidth(formatted_port, line)
                                if "RX" in line:
                                    print("Input bandwidth: {:6.1f} Mbps".format(bw))
                                else:
                                    print("Output bandwidth: {:5.1f} Mbps".format(bw))
                            if "OP" in line:
                                if "ROP" not in line:
                                    power = line.split()[3]
                                    if "IOP" in line:
                                        print("Rx power: {} dBm".format(power))
                                    else:
                                        print("Tx power: {} dBm".format(power))
                if args.config:
                    if teng_check(formatted_port):
                        telnet.write(b"sho run inter ten " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(config_sleep)
                        print("\nCONFIG TENG {}".format(port))
                        print_output(telnet.read_very_eager())

                    elif formatted_port[2]=="5":
                        telnet.write(b"sho run inter cep " + formatted_port.encode('ascii') + b"/1/0\n")
                        time.sleep(config_sleep)
                        print("\nCONFIG STM-1 {}".format(port))
                        print_output(telnet.read_very_eager())
                    elif formatted_port[0] == "l":
                        telnet.write(b"sho run inter " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(config_sleep)
                        print("\nCONFIG {}".format(formatted_port.upper()))
                        print_output(telnet.read_very_eager())
                    else:
                        telnet.write(b"sho run inter gi " + formatted_port.encode('ascii') + b"\n")
                        time.sleep(config_sleep)
                        print("\nCONFIG GI {}".format(port))
                        print_output(telnet.read_very_eager())

                if args.performance:
                    if formatted_port[0] == "l":
                        continue
                    telnet.write(b"sho performance slot " + formatted_port[2].encode('ascii') + b" filter " + formatted_port.encode('ascii') + b"\n")
                    time.sleep(sleep)
                    print("\nCURRENT PERFORMANCE of PORT {}".format(port))
                    print_output(telnet.read_very_eager())

                    telnet.write(b"sho performance-cumu slot " + formatted_port[2].encode('ascii') + b" filter " + formatted_port.encode('ascii') + b"\n")
                    time.sleep(sleep)
                    print("\nCUMULATIVE PERFORMANCE of PORT {}".format(port))
                    print_output(telnet.read_very_eager())

        if args.system:
            telnet.write(b"ems system-usage\n")
            time.sleep(sleep)
            print("\nSYSTEM USAGE for NODE: {}".format(ip))
            print_output(telnet.read_very_eager())
            print("\n")
                
        if args.version:
            telnet.write(b"ems version compile\n")
            time.sleep(sleep)
            print("\nSYSTEM VERSION for NODE: {}\n".format(ip))
            print_output(telnet.read_very_eager())
            print("\n")
            
        if args.alarm:
            telnet.write(b"sho current-alarm all\n")
            time.sleep(sleep)
            print("\nCURRENT ALARM for NODE: {}\n".format(ip))
            print_output(telnet.read_very_eager())
            print("\n")

        # if args.config:
            # telnet.write(b"conf t\n")
            # time.sleep(sleep)
            # telnet.write(b"terminal length 0\n")
            # time.sleep(sleep)
            # telnet.write(b"exit\n")
            # time.sleep(sleep)
            # telnet.write(b"sho run\n")
            # print("\nSYSTEM CONFIG")
            # time.sleep(12)
            # print_output(telnet.read_very_eager())
            # print("\n")
        
        telnet.close()

    except:
        print("\n\nIP {} : Timeout Error!!!\n\n".format(ip))
