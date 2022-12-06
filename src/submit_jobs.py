"""
    Code used to submit jobs to Dalton.

    Input:
        Path to the Original Rule.
        Path to various PCAPs
    Outputs:
        JobID for each PCAP

"""
import requests
import argparse
import time
import json
import random
import sys
import os

DALTON_HOST = "localhost"
# RULE_SET_RELATIVE_PATH = "rules"
ENGINE_CONFIG_RELATIVE_PATH = "engine_configs"

ENGINES_LIST = ["snort2"]

# List of Engines
ENGINE_MAP = {
    "snort2": "snort/2.9.15.1",
    "snort3": "",
    "suricata": "",
    "zeek": ""
}

DUT_EngineConfigs = {
    'snort/2.9.15.1': "snort_engine_2_9_15_1.conf"
}

DUT_EngineProdRules = {
    "snort/2.9.15.1": "/opt/dalton/rulesets/snort/emerging-web_client.rules",
    "snort3": "",
    "suricata": "",
    "zeek": ""
}

# Default Values
HTTP_POST_Request = {
    "sensor_tech": "",
    "optionUseSC": "use_sock_control",
    "prod_ruleset": "",
    "optionCustomRuleset": "custom",
    "custom_ruleset": "",
    "optionAlertDetailed": "optionAlertDetailed",
    "optionSplitcap": "splitcap", 
    "overrideExternalNet": "eoverride",
    "custom_engineconf": "",
    "teapotJob": 1
}

parser = argparse.ArgumentParser()


def arguments_init():
    parser.add_argument('-r', '--rule', help='Input Rule from which the pcaps has been generated')
    parser.add_argument('-o', '--output', help='Output JSON file to dump')
    parser.add_argument('-p', '--pcaps', help='Comma Separated list of pcaps which were generated for the rule, first one is the original without evasions')
    parser.add_argument('-e', '--engine', help='Comma Separated list of engines to use. default: snort2')
    args = parser.parse_args()
    return args


def upload_to_dalton(rule, pcaps):
    """
        For a single rule there could be multiple PCAPs

        Response:
        {
            engine_type:{
                'pcap1':'id',
                'pcap2': 'id2;
            }
        }
    """
    pcap_list = pcaps.split(",")
    engine_list = ENGINES_LIST
    response_map = {}
    for each_engine in engine_list:
        # We upload a bunch of test for a specific Engines
        engine_actual_name = ENGINE_MAP[each_engine]
        config_engine = DUT_EngineConfigs[engine_actual_name]
        prod_rules = DUT_EngineProdRules[engine_actual_name]
        file_to_upload = {}
        for pcap_id, pcap_name in enumerate(pcap_list):
            key_ = "coverage-pcap" + str(pcap_id)
            with open(pcap_name, 'rb') as pcap_data:
                file_to_upload[key_] = (pcap_name, pcap_data.read())
        # testing with single PCAP upload
        HTTP_POST_Request["sensor_tech"] = engine_actual_name
        HTTP_POST_Request["prod_ruleset"] = prod_rules

        # read the rule_set
        with open(rule, "r") as fp_rule:
            rule_text = fp_rule.read()

        with open(os.path.join(ENGINE_CONFIG_RELATIVE_PATH, config_engine), "r") as fp_engine_conf:
            engine_config_text = fp_engine_conf.read()

        HTTP_POST_Request["custom_ruleset"] = rule_text
        HTTP_POST_Request["custom_engineconf"] = engine_config_text

        response = requests.post(f"http://{DALTON_HOST}/dalton/coverage/summary",
                                 data=HTTP_POST_Request,
                                 files=file_to_upload)

        teapot_ids = response.text.split(",")
        pcaps_map = {}
        for pcap_id, pcap_name in enumerate(pcap_list):
            pcaps_map[pcap_name] = {"id": teapot_ids[pcap_id]}

        response_map[each_engine] = pcaps_map
    print(response_map)
    return response_map

def check_result_in_dalton(jobs):
    """
        {'snort2': 'teapot_069c73c807df1270,teapot_05033da62c56c67f'}
    """
    for each_engine in jobs:
        for each_pcap in jobs[each_engine]:
            # lets sleep for some more time to allow the server to process all the records.
            time.sleep(random.choice(range(10,20)))
            each_id = jobs[each_engine][each_pcap]["id"]
            alert_text = requests.get(f"http://{DALTON_HOST}/dalton/controller_api/v2/{each_id}/all")
            response_for_id = alert_text.json()
            jobs[each_engine][each_pcap]["alert"] = response_for_id["data"]["alert"]
            jobs[each_engine][each_pcap]["error"] = response_for_id["data"]["error"]
            with open(f"outputs/dalton_results/all/{each_id}.json", "w") as json_fp:
                json.dump(response_for_id, json_fp, indent=2)
    return jobs


def submit_jobs_to_dalton_main(input_rule, input_pcaps, output):
    job_ids = upload_to_dalton(input_rule, input_pcaps)
    # sleep for some time to allow the pcaps to be processed.
    time.sleep(random.choice(range(30,60)))
    output_json = check_result_in_dalton(job_ids)
    """
        OutPut Format
        {
            'snort2':
                {'../demo/http_version_v.pcap':{
                    'id':'teapot_c8e976b13aa82346',
                    'alert':''},
                '../demo/http_version_iv.pcap':{
                    'id': 'teapot_3915b6ddd9e0ecf2',
                    'alert':''
                    }
                }
        }
    """
    with open(output, "w") as json_fp:
        json.dump(output_json, json_fp, indent=2)
    return output_json


def main(arguments):
    options = arguments_init()
    # lets check the arguments
    input_rule = options.rule
    input_pcaps = options.pcaps
    output_file = options.output
    engines = options.engine
    if not input_pcaps or not input_rule:
        parser.print_help()
        exit(1)
    if not output_file:
        output_file = 'test_output.json'
    if not engines:
        engines = 'snort2'

    submit_jobs_to_dalton_main(input_rule, input_pcaps, output_file)


if __name__ == "__main__":
    main(sys.argv)
