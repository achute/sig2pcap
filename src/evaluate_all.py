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
from multiprocessing.dummy import Pool as ThreadPool

from scapy_http_manipulations import parse_pcap_modify_http
from submit_jobs import submit_jobs_to_dalton_main, ENGINES_LIST

parser = argparse.ArgumentParser()

valid_json = {}

PRESENT_DIR = os.getcwd()
INTERMEDIATE_RULES_DIR = "outputs/rules/"
INTERMEDIATE_PCAP_DIR = "outputs/pcaps/"
INTERMEDIATE_DALTON_RESULTS = "outputs/dalton_results/alerts"
DEFAULT_FILES_DIR = "outputs/default_files/"

RESULT_MAP = {
    'ERROR': -1,
    'TP': 1,
    'FP': 2,
    'FN': 3
}


# Evasions 
HTTP_EVASIONS = ['method', 'version_valid', 'version_invalid']

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


def apply_evasions_to_pcap(in_pcap):
    # Apply the evasions and save the pcap in a folder meant for a parent.
    # input, output , evasion
    original_pcap_path = in_pcap.split(".pcap")[0]
    evaded_pcaps = []
    # HTTP Evasions
    for http_evasion_ in HTTP_EVASIONS:
        output_pcap_ = original_pcap_path + str("_") + http_evasion_ + str(".pcap")
        evade_pcap_correct = parse_pcap_modify_http(in_pcap, output_pcap_, http_evasion_)
        if evade_pcap_correct:
            evaded_pcaps.append(output_pcap_)
    return evaded_pcaps


def upload_pcaps_to_dalton(input_rule, parent_pcap, evaded_pcap_list, output_file):
    # submit_jobs_to_dalton_main(input_rule, input_pcaps, engines, output)
    # First pcap is parent
    if evaded_pcap_list:
        pcaps_ = parent_pcap + str(",") + ','.join(evaded_pcap_list)
    else:
        pcaps_ = parent_pcap
    print(pcaps_)
    response_from_dalton = submit_jobs_to_dalton_main(input_rule, pcaps_, output_file)
    return response_from_dalton


def alerts_are_same(msg, full_alert):
    # full alert is usually 
    """
        [**] [1:2016327:2] ET CURRENT_EVENTS Possible Successful Phish - Generic POST to myform.php Feb 01 2013 [**]\n[Classification: Potentially Bad Traffic] [Priority: 2] \n01/01-00:00:00.000002 192.168.0.1:40148 -> 154.201.11.127:901\nTCP TTL:40 TOS:0x0 ID:0 IpLen:20 DgmLen:94\n***A**** Seq: 0x5A745136  Ack: 0x98F26FF6  Win: 0xFDE8  TcpLen: 20\n\n",
    """
    stripped_msg = full_alert.split("\n")[0].split("[**]")[1].split("]")[1].strip()
    if msg.strip() == stripped_msg:
        return True
    return False


def analyze_the_results(rule_parsed_dict, rule_id, results_of_upload):
    """
        Error:
            Error in the parent
            Error in the child
        
        -1 -> Error
        1 -> True Positive: triggers Rule R
        2 -> False Positive: triggers any other rules than Rule R 
        3 -> Fase Negative: does not trigger Rule R.

            True Negative: Random generated PCAPs triggers a rule ( True Negative ) – We are not testing for these.

        Testing for evasions is usually the reverse. 
            So if it does not trigger the rule when it had previously is good from Evasion Perspective.
        
        Response 
        {
            sid: {
                parent: 1 -> Single Result
                child: [-1,2,1] -> List of results per child
            }
        }
    """
    response_dict = {}
    response_dict[rule_id] = {
        'parent':0,
        'child':[]
    }
    for each_engine in results_of_upload:
        parent_done = False
        for each_pcap in results_of_upload[each_engine]:
            # first one is always the parent
            if results_of_upload[each_engine][each_pcap]["error"] != "":
                result_each = "ERROR"
            elif results_of_upload[each_engine][each_pcap]["alert"] == "*** No Alerts ***\n":
                result_each = "FN"
            elif alerts_are_same(rule_parsed_dict["msg"], results_of_upload[each_engine][each_pcap]["alert"]):
                result_each = "TP"
            else:
                result_each = "FP"
            
            if not parent_done:
                response_dict[rule_id]["parent"] = RESULT_MAP[result_each]
                parent_done = True
            else:
                response_dict[rule_id]["child"].append(RESULT_MAP[result_each])
    return response_dict


def print_results(result):
    parent_tp = 0
    parent_fn = 0
    parent_fp = 0
    parent_error = 0
    parent_unknwn = 0
    child_tp = 0
    child_fn = 0
    child_fp = 0
    child_error = 0
    child_unknwn = 0
    """
    'TP': 1,
    'FP': 2,
    'FN': 3
    """

    for each_rule in result:
        for sid in each_rule:
            parent_result =  each_rule[sid]["parent"]
            if parent_result == -1:
                parent_error += 1
            elif parent_result == 1:
                parent_tp += 1
                print("SID TP : ",sid)
            elif parent_result == 2:
                parent_fp += 1
                print("SID FP : ",sid)
            elif parent_result == 3:
                parent_fn += 1
            else:
                parent_unknwn += 1
            child_results = each_rule[sid]["child"]
            for each_child_res in child_results:
                if each_child_res == -1:
                    child_error += 1
                elif each_child_res == 1:
                    child_tp += 1
                    print("CHILD TP : ",sid)
                elif each_child_res == 2:
                    child_fp += 1
                    print("CHILD FP : ",sid)
                elif each_child_res == 3:
                    child_fn += 1
                else:
                    child_unknwn += 1
        
    # END results
    print("\n --Results -- \n")
    print("Parent:\n")
    print(f"True Positive {parent_tp}")
    print(f"False Positive {parent_fp}")
    print(f"False Negative {parent_fn}")
    print(f"Error {parent_error}")
    print(f"Unknowns {parent_unknwn} \n")
    print("Evaded PCAPs:\n")
    print(f"True Positive {child_tp}")
    print(f"False Positive {child_fp}")
    print(f"False Negative {child_fn}")
    print(f"Error {child_error}")
    print(f"Unknowns {child_unknwn} \n")
        

def process_single_valid_rule(valid_rule):
    global valid_json
    results_json_from_dalton = os.path.join(INTERMEDIATE_DALTON_RESULTS, valid_rule) + str(".json")
    if not os.path.isfile(results_json_from_dalton):
        # Process the rule.
        rule_filepath = os.path.join(INTERMEDIATE_RULES_DIR, valid_rule) + str(".rule")
        dump_a_rule_to_file(rule_filepath, valid_json[valid_rule]['raw'])
        # Create a PCAP from this rule
        parent_pcap_file = os.path.join(INTERMEDIATE_PCAP_DIR, valid_rule) + str(".pcap")
        generate_pcap_for_rule(rule_filepath, parent_pcap_file)
        # Apply Evasions to these PCAP
        evaded_pcaps = apply_evasions_to_pcap(parent_pcap_file)
        # Upload The PCAPs
        results_of_upload = upload_pcaps_to_dalton(rule_filepath,
                                                parent_pcap_file,
                                                evaded_pcaps,
                                                results_json_from_dalton)
    else:
        with open(results_json_from_dalton, "r") as valid_rules_fp:
            results_of_upload = json.load(valid_rules_fp)
    final_result_each = analyze_the_results(valid_json[valid_rule], valid_rule, results_of_upload)
    return final_result_each


def process_all_valid_rule():
    global valid_json
    # For each valid rule -> Convert ; Evade ; Upload; Analyze; Dump 
    # # /home/kali/Practicum/tools/rules/test/practicum/outputs/rules/1_2016327.rule 
    final_results = {}
    pool = ThreadPool(20)

    # Process each SID in their own threads
    # and return the results
    final_result_each = pool.map(process_single_valid_rule, valid_json)
    # Close the pool and wait for the work to finish
    pool.close()
    pool.join()

    
    print_results(final_result_each)



def main(arguments):
    global valid_json
    options = arguments_init()
    # lets check the arguments
    input_rule = options.rule
    input_valid = options.valid
    output_file = options.output
    if not input_rule and not input_valid:
        parser.print_help()
        exit(1)
    if not output_file:
        output_file = os.path.join(DEFAULT_FILES_DIR, 'valid_rules_default.json')

    if not input_valid:
        valid_rules = parse_rule(input_rule)
        with open(output_file, "w") as valid_rules_fp:
            json.dump(valid_rules, valid_rules_fp, indent=2)
    else:
        with open(input_valid, "r") as valid_rules_fp:
            valid_rules = json.load(valid_rules_fp)

    print("Total Number of Valid Rules %d" % (len(valid_rules)))
    valid_json = valid_rules
    process_all_valid_rule()


if __name__ == "__main__":
    # parse_rule("single_http.rule")
    main(sys.argv)