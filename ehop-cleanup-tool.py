import json
import subprocess
import platform
import time
import csv
from datetime import datetime
import requests as requests
import urllib3
import re

eh_host = "192.168.0.06"  #  Insert your EDA/ECA's hostname or IP address
eh_apikey = "NI28wKoSGTHHWVEwGqesq8wMYJQBkT88oTEG4L5rpMs"           #  Add your API key here
headers = {'Accept': 'application/json', 'Authorization': "ExtraHop apikey={}".format(eh_apikey)}

# Should we verify the EDA or ECA's server SSL/TLS certificate?
eh_verify_cert = False

#  If we see there's no description for a trigger, should we generate a generic one with a list of metrics that are
#  created by the trigger?
update_descriptions = False

#  If we're adding a description, how many of the metrics a trigger generates should be included in the description?
#  The default of 40 is recommended
description_metric_count = 40

# If we find a trigger with 'debug' enabled, should we disable this? Having debug enabled on a trigger can produce
# additional load on an EDA
disable_debug_for_triggers = False

# Should we write out to a CSV file?

write_csv = True

#  Should we write out to a txt file?

write_txt = True

#  Should we write details of user accounts to a seperate file?

write_users = True

#  Should we just ping the EDA and exit?

ping = True

def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return_code = subprocess.run(command).returncode
    print("Return code is " + str(return_code))
    return return_code


def get_trigger_list():
    url = "https://{}/api/v1/triggers/".format(eh_host)
    try:
        r = requests.get(url, headers=headers, verify=eh_verify_cert)
    except Exception as e:
        print("Issue encountered while sending an API request to {}. Details: {}".format(url, e))
        raise
    # handle non 200 response
    if r.status_code >= 200 and r.status_code < 300:
        print("Retrieved list of triggers from the EDA {} ".format(eh_host))
    else:
        print(("Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
            r.status_code, url, r.text)))
        raise ValueError(
            "Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
                r.status_code, url,
                r.text))
    return r.json()


def update_trigger_description(trigger_id, description):
    url = "https://{}/api/v1/triggers/{}".format(eh_host, trigger_id)
    description_string = "{ \"description\": \"" + description + "\"}"
    #  description_in_json = json.loads(description_string)
    #  print(json.dumps(description_in_json))
    try:
        r = requests.patch(url, description_string, headers=headers, verify=eh_verify_cert)
    except Exception as e:
        print("Issue encountered while sending an API request to {}. Details: {}".format(url, e))
    #  handle non 200 response

    if 200 <= r.status_code < 300:
        print("Updated description for trigger {} ".format(r.status_code))
        return
    else:
        print(("Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
            r.status_code, url, r.text)))
        raise ValueError(
            "Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
                r.status_code, url,
                r.text))


def disable_debug_on_trigger(trigger_id):
    url = "https://{}/api/v1/triggers/{}".format(eh_host, trigger_id)
    debug_string = "{ \"debug\": false }"
    #  print("Debug json is " + debug_string)
    try:
        r = requests.patch(url, debug_string, headers=headers, verify=eh_verify_cert)
    except Exception as e:
        print("Issue encountered while sending an API request to {}. Details: {}".format(url, e))
    #  handle non 200 response

    if 200 <= r.status_code < 300:
        print("Updated description for trigger {} ".format(r.status_code))
        return
    else:
        print(("Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
            r.status_code, url, r.text)))
        raise ValueError(
            "Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(
                r.status_code, url,
                r.text))
    return


def extract_metric_statement(trigger_line):
    # This regex looks for words within brackets
    regex = '\(([^)]+)'
    words_in_quotes = re.findall(regex, trigger_line)
    for word in words_in_quotes:
        word = word.replace("'", "")  # Strip single quotes
        word = word.replace('"', "")  # Strip double quotes
        word_parts = word.split(",")  # Split on the comma of the metricAddCount("abc", 1) statement
        word = word_parts[0].strip()  # Strip any whitespace and take the first word.
        #  print("Metric name is " + word)
    return word


def check_metrics_added(trigger_name, trigger_script):
    found_count = 0
    metrics_list = []
    trigger_code_in_lines: object = trigger_script.splitlines()
    #  print("Checking trigger " + trigger_name)
    for this_line in trigger_code_in_lines:
        for match in re.finditer('.metricAdd', this_line, re.MULTILINE):
            metrics_list.append(extract_metric_statement(this_line.strip()))
            found_count = found_count + 1
    if found_count > 0:
        return found_count, metrics_list
    else:
        return 0, ""


def write_results_to_txt_file(triggers):
    today = datetime.today().strftime(('%Y-%m-%d'))
    today_for_file = datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
    filename = "trigger_metrics-" + today + ".txt"
    with open(filename, 'w') as file_write_out:
        file_write_out.write("----------------------------------------------\n")
        file_write_out.write("ExtraHop Trigger list as of " + today_for_file + "\n")
        file_write_out.write("----------------------------------------------\n\n")

        for trigger in triggers:
            # Convert the Unix Epoch time (divided by 1000) to a date string
            mod_time_seconds = trigger["mod_time"] / 1000
            trigger["mod_time_readable"] = time.ctime(mod_time_seconds)
            #  check_description(trigger["description"])
            file_write_out.write("\tTrigger Name: " + trigger['name'] + "\n")
            file_write_out.write("\tTrigger Last Modified: " + trigger['mod_time_readable'] + "\n")
            file_write_out.write("\tTrigger Desc: " + str(trigger['description']) + "\n")
            file_write_out.write("\tTrigger Author: " + trigger['author'] + "\n")
            file_write_out.write("\tTrigger Disabled: " + str(trigger['disabled']) + "\n")
            file_write_out.write("\tTrigger Debug: " + str(trigger['debug']) + "\n")
            file_write_out.write("\tTrigger Apply to All: " + str(trigger['apply_all']) + "\n")
            file_write_out.write("\tTrigger API ID: " + str(trigger['id']) + "\n")

            #  Write out the events that this trigger fires on.
            for event in trigger['events']:
                file_write_out.write("\tTrigger Event: " + event + "\n")
            #  Count the number of times 'metricAdd appears in this script and get the occurrences
            metric_add_count, metric_names_list = check_metrics_added(trigger['name'], trigger['script'])
            if metric_add_count > 0:
                #  print("Metric addition statements found " + str(metric_add_count) + " times in trigger " + trigger[
                #    'name'] + "\n")
                file_write_out.write("\tA total of " + str(metric_add_count) + " metrics created by this trigger\n")
                for metric_name in metric_names_list:
                    file_write_out.write("\t\tMetric name: " + str(metric_name) + "\n")
                file_write_out.write("\n\n")
                #  If this trigger doesn't have a description, add an autogenerated one that lists some of the metrics
                #  that are created. Limited to the total number or twenty

            else:
                file_write_out.write("\tNo metrics created by this trigger")
                file_write_out.write("\n\n")


def write_results_to_csv_file(triggers):
    today = datetime.today().strftime(('%Y-%m-%d'))
    today_for_file = datetime.today().strftime(('%Y-%m-%d-%H:%M:%S'))
    filename = "trigger_metrics-" + today + ".csv"

    csv_columns = ['mod_time_readable', 'id', 'name', 'description', 'author', 'events', 'disabled', 'debug', 'apply_all', 'hints', 'metrics_created']
    with open(filename, 'w', newline='') as csvfile_out:
        csv_writer = csv.DictWriter(csvfile_out, fieldnames=csv_columns)
        csv_writer.writeheader()
        for trigger in triggers:
            this_row = ""
            # Convert the Unix Epoch time (divided by 1000) to a date string
            mod_time_seconds = trigger["mod_time"] / 1000
            trigger["mod_time_readable"] = time.ctime(mod_time_seconds)
            metric_add_count, metric_names_list = check_metrics_added(trigger['name'], trigger['script'])
            if metric_add_count > 0:
                #  print("Metric addition statements found " + str(metric_add_count) + " times in trigger " + trigger[
                #    'name'] + "\n")
                # csvfile_out.write("\tA total of " + str(metric_add_count) + " metrics created by this trigger\n")
                metric_list = ""
                for metric_name in metric_names_list:
                    metric_list = metric_list + str(metric_name) + " "
                    trigger['metrics_created'] = metric_list

            else:
                trigger["metrics_created"] = 'None'
            del trigger["mod_time"]
            del trigger["script"]
            del trigger["event"]
            csv_writer.writerow(trigger)


def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    triggers = get_trigger_list()
    if write_txt:
        write_results_to_txt_file(triggers)

    if write_csv:
        write_results_to_csv_file(triggers)

    for trigger in triggers:
        if not trigger['description'] and update_descriptions is True:
            #  print("No description for trigger " + trigger['name'] + ". Adding a machine generated one")
            description = "This description automatically added. This trigger adds in the following metrics: "
            # We'll populate up to description_metric_count (default:40) metrics into the machine-generated
            # description
            if len(metric_names_list) >= description_metric_count:
                for i in range(description_metric_count):
                    description = description + metric_names_list[i]
            else:
                for i in range(len(metric_names_list)):
                    description = description + metric_names_list[i] + ", "
            #  print("Auto description is " + description)
            update_trigger_description(trigger['id'], description)
        #  else:
            #  print("Trigger has an existing description of " + trigger['description'] + ". No update required")

        if True == trigger['debug'] and disable_debug_for_triggers is True:
            #  print("Debug flag enabled for trigger and disable_debug is enabled. Disabling")
            disable_debug_on_trigger(trigger['id'])


if __name__ == '__main__':
    result = ping(eh_host)
    print("Result is " + str(result))
    main()
