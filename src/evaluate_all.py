"""
    Main Program to do the following:
        Read a Rule from a single File with many rules.
        create a separate rule out of each valid rule:
            valid rules are rules with HTTP. // since the evasions are focused for HTTP traffic.
        take each valid rule from a set of valid rules
            Convert the rule to PCAP. // call sniffels
            Take each pcap and apply evasions // partially done
            take the pcaps and upload to Dalton // done
            process the response.
"""
import os
import sys
import json
import argparse
import subprocess
from idstools import rule

parser = argparse.ArgumentParser()

PRESENT_DIR = os.getcwd()
INTERMEDIATE_RULES_DIR = "outputs/rules/"
INTERMEDIATE_PCAP_DIR = "outputs/pcaps/"

def arguments_init():
    parser.add_argument('-r', '--rule', help='Input Rule (raw) from which the pcaps are to be generated')
    parser.add_argument('-v', '--valid', help='Input Valid Rule (json) from which the pcaps will be generated')
    parser.add_argument('-o', '--output', help='Output JSON file to dump the valid rules')
    args = parser.parse_args()
    return args


def print_rule(rule_file):
    for each_rule in rule.parse_file(rule_file):
        print("[%d:%d:%d] %s" % (
            each_rule.gid, each_rule.sid, each_rule.rev, each_rule.msg))

def parse_rule(rule_file):
    valid_rules = {}
    for each_rule in rule.parse_file(rule_file):
        if each_rule.enabled:
            # Rule must be enabled
            if 'tcp' in each_rule.header or 'http' in each_rule.header:
                # Rule must have TCP or HTTP in the header
                id_string = "_".join(each_rule.idstr.rstrip("]").lstrip("[").split(":"))
                valid_rules[id_string] = {
                    'raw': each_rule.raw,
                    'sid': each_rule.sid,
                    'msg': each_rule.msg
                }
    return valid_rules

def dump_a_rule_to_file(file_path, rule_raw):
    with open(file_path, "w") as each_rule_fp:
        each_rule_fp.write(rule_raw)

def execute_os_command(os_command):
    cmd = subprocess.Popen(os_command)
    cmd.wait()

def generate_pcap_for_rule(rule, out_pcap):
    local_cmd = ["sniffles", "-e", "-t", "-h 192.168.0.1"]
    local_cmd.append(f"-f{os.path.join(PRESENT_DIR,rule)}")
    local_cmd.append(f"-o{os.path.join(PRESENT_DIR,out_pcap)}")
    #print(" ".join(local_cmd))
    execute_os_command(local_cmd)


def process_each_valid_rule(valid_json):
    # For each valid rule -> Convert ; Evade ; Upload; Analyze; Dump 
    # # /home/kali/Practicum/tools/rules/test/practicum/outputs/rules/1_2016327.rule 
    for each_valid_rule in valid_json:
        # Dump the Rule
        rule_filepath = os.path.join(INTERMEDIATE_RULES_DIR, each_valid_rule) + str(".rule")
        dump_a_rule_to_file(rule_filepath, valid_json[each_valid_rule]['raw'])
        # Create a PCAP from this rule
        parent_pcap_file = os.path.join(INTERMEDIATE_PCAP_DIR, each_valid_rule) + str(".pcap")
        generate_pcap_for_rule(rule_filepath, parent_pcap_file)
        # Apply Evasions to these PCAP
        # Upload The PCAPs
        # Analyze the uploads
        # Dump the result in continious file


def main(arguments):
    options = arguments_init()
    # lets check the arguments
    input_rule = options.rule
    input_valid = options.valid
    output_file = options.output
    if not input_rule and not input_valid:
        parser.print_help()
        exit(1)
    if not output_file:
        output_file = 'valid_rules_default.json'

    if not input_valid:
        valid_rules = parse_rule(input_rule)
        with open(output_file, "w") as valid_rules_fp:
            json.dump(valid_rules, valid_rules_fp, indent=2)
    else:
        with open(input_valid, "r") as valid_rules_fp:
            valid_rules = json.load(valid_rules_fp)

    print("Total Number of Valid Rules %d" % (len(valid_rules)))
    process_each_valid_rule(valid_rules)


if __name__ == "__main__":
    # parse_rule("single_http.rule")
    main(sys.argv)