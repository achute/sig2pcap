"""
    Program to Manipulate HTTP Packets using scapy.

    How the program works ?

    All the Packets in the PCAP file will be affected by the same logic.
    i.e if all of them needs their methods change it will affect all the packets.


    All of the modifications will be random, with a fixed seed whose value can be changed.


    http_manipulate.py --input input_pcap --output output_pcap --evasion <all, method, version_valid, version_invalid, payload_append>

"""
import os
import sys
import random
import argparse
import hashlib

# SCAPY Imports
from scapy.all import *
from scapy.layers.http import *
from scapy.layers.http import HTTPRequest

# Clour Text
from colorama import init
from termcolor import colored

# Specific Imports
import lorem

init()

# SCAPY packets checksums to reset
scapy_fix_chksum = [scapy.layers.inet.IP,
                    scapy.layers.inet.TCP,
                    scapy.layers.inet.UDP,
                    scapy.layers.inet.ICMP]

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
HTTP_METHODS = [b'OPTIONS', b'GET', b'POST', b'PUT',
                b'PATCH', b'DELETE', b'HEAD', b'CONNECT', b'TRACE']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP
HTTP_VALID_VERSION_DECIMAl = [b'0.9', b'1.0', b'1.1', b'2.0', b'3.0']


# Valid Evasions
valid_evasions = ['all', 'method', 'version_valid', 'version_invalid', 'random_append']


def console_log(message, fore_ground='white', bg='on_green'):
    print(colored(message, fore_ground, bg))


parser = argparse.ArgumentParser()


def arguments_init():
    parser.add_argument('-i', '--input', help='Input PCAP file to process')
    parser.add_argument('-o', '--output', help='Output PCAP file to dump')
    parser.add_argument('-e', '--evasion', help='Evasion to perform')
    args = parser.parse_args()
    return args


def random_choice(list_to_select_from, item_to_exclude):
    valid_choice = False
    while not valid_choice:
        selection = random.choice(list_to_select_from)
        if selection != item_to_exclude:
            valid_choice = True
    return selection


def random_generation(type='http_version', list_to_exclude=HTTP_VALID_VERSION_DECIMAl):
    if type == 'http_version':
        # Need to generate a decimal number
        valid_choice = False
        while not valid_choice:
            http_major = random.choice(range(0,10))
            http_minor = random.choice(range(0, 10))
            full_version = bytes(str(http_major), 'utf-8') + b'.' + bytes(str(http_minor), 'utf-8')
            if full_version != list_to_exclude:
                valid_choice = True
        return full_version
    else:
        return random.choice(range(0, 10))


def fix_checksum(packet):
    for packet_layer in scapy_fix_chksum:
        try:
            packet.getlayer(packet_layer).chksum = None
        except:
            pass


def confirm_http_packet(packet):
    """
        This method should have some checks in place to confirm
        if the packet in question is indeed an HTTP packet

        We already check for packets starting with the HTTP Methods above,
         so ignore for now.

        TODO: Perform the checks
    """
    return True


def modify_http_method(packet):
    try:
        last_layer_payload = packet.lastlayer().load
        present_message = bytes(last_layer_payload).split(b' ')
        present_method = present_message[0]
        # randomly pick up a method which is not present in message
        new_method = random_choice(HTTP_METHODS, present_method)
        present_message[0] = new_method
        packet.lastlayer().load = b' '.join(present_message)
        console_log('[HTTP] METHOD Modified to - {} '.format(new_method.decode()))
        return packet
    except:
        return packet


def modify_http_version_valid(packet):
    try:
        last_layer_payload = packet.lastlayer().load
        present_message = last_layer_payload.split(b'\r\n')  # Line Wise
        present_http_line = present_message[0].split(b' ')
        present_http_version = present_http_line[-1].split(b'/')[-1]
        # randomly pick up a valid HTTP version which is not present in message
        new_valid_version = random_choice(HTTP_VALID_VERSION_DECIMAl, present_http_version)

        new_http_version = b'HTTP/' + new_valid_version
        present_http_line[-1] = new_http_version
        new_http_line = b' '.join(present_http_line)
        present_message[0] = new_http_line
        packet.lastlayer().load = b'\r\n'.join(present_message)
        console_log('[HTTP] Version Modified to - {} '.format(new_http_version.decode()))
        return packet
    except:
        return packet


def modify_http_version_invalid(packet):
    try:
        last_layer_payload = packet.lastlayer().load
        present_message = last_layer_payload.split(b'\r\n')  # Line Wise
        present_http_line = present_message[0].split(b' ')
        # randomly pick up a valid HTTP version which is not present in message
        new_invalid_version = random_generation('http_version', HTTP_VALID_VERSION_DECIMAl)
        new_http_version = b'HTTP/' + new_invalid_version
        present_http_line[-1] = new_http_version
        new_http_line = b' '.join(present_http_line)
        present_message[0] = new_http_line
        packet.lastlayer().load = b'\r\n'.join(present_message)
        console_log('[HTTP] Invalid Version Modified to - {} '.format(new_http_version.decode()))
        return packet
    except:
        return packet


def modify_http_payload_random_append(packet):
    # FIXME: Not working.
    # Might need to the reset the length in the TCP layer.
    last_layer_payload = packet.lastlayer().load
    present_message = last_layer_payload.split(b'\r\n')  # Line Wise
    # Add content to the last line..
    new_content = bytes(lorem.text(), 'utf-8')
    present_message.append(new_content)
    packet.lastlayer().load = b'\r\n'.join(present_message)
    console_log('[HTTP] Payload Random Append - Done ')
    return packet

def modify_url_to_self_reference(packet):
    # if there are / in the URL then self reference them.
    pass

def get_md5_hash(file):
    with open(file, 'rb') as file_fp:
        data_ = file_fp.read()
        md5_return = hashlib.md5(data_).hexdigest()
    return md5_return


def parse_pcap_modify_http(input_pcap, output_pcap, evasion):
    """
        HTTP layers were not getting detected and packet.haslayer(HTTPRequest)
        was not working

        Hence resorted to extracting the TCP payload.
        if the payload starts with any of the HTTP methods than 
        it most likely is an HTTP packet.
    """
    packets = []
    for packet in PcapReader(input_pcap):
        packet_could_be_http = False
        try:
            payload = bytes(packet[TCP].payload)
            if payload.startswith(tuple(HTTP_METHODS)):
                packet_could_be_http = True
        except Exception as e:
            packets.append(packet)
            pass
        if packet_could_be_http:
            # confirm its an HTTP packet
            if confirm_http_packet(packet):
                if evasion == 'all':
                    modify_http_method(packet)
                    modify_http_version_valid(packet)
                    modify_http_version_invalid(packet)
                    modify_http_payload_random_append(packet)
                elif evasion == 'method':
                    modify_http_method(packet)
                elif evasion == 'version_valid':
                    modify_http_version_valid(packet)
                elif evasion == 'version_invalid':
                    modify_http_version_invalid(packet)
                elif evasion == 'random_append':
                    packet = modify_http_payload_random_append(packet)
                fix_checksum(packet)
        # add the original packet or the modified one to the list.
        packets.append(packet)
    # dump the packets to a PCAP file.
    wrpcap(output_pcap, packets)
    # Check if input pcap and the output pcap is the same
    # if same remove the file and return False
    # else return True
    old_hash = get_md5_hash(input_pcap)
    new_hash = get_md5_hash(output_pcap)
    if new_hash == old_hash:
        print("Modification Unsucessful. Removing PCAP")
        os.remove(output_pcap)
        return False
    return True





def main(arguments):
    options = arguments_init()
    # lets check the arguments
    input_pcap = options.input
    output_pcap = options.output
    evasion = options.evasion
    if not input_pcap or not output_pcap:
        parser.print_help()
        exit(1)
    if not evasion:
        evasion = 'all'
    if evasion not in valid_evasions:
        parser.print_help()
        print("Invalid Evasion specified valid evasions are {}".format(valid_evasions))
        exit(1)

    parse_pcap_modify_http(input_pcap, output_pcap, evasion)


if __name__ == "__main__":
    main(sys.argv)