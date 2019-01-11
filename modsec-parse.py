import argparse
import sys
import re

def get_options(cmd_args=None):
    """
    Parse command line arguments
    """
    cmd_parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    cmd_parser.add_argument(
        '-i',
        '--input_log_file',
        help="""a text file where each line holds a different URL where to search for WP""",
        type=str,
        default='modsec_audit.log')

    args = cmd_parser.parse_args(cmd_args)

    options = {}
    options['input_log_file'] = args.input_log_file

    return options

def main(opts):

    f = open(opts['input_log_file'],"r")
    entries         = {}
    current_entry   = ""
    current_section = ""

    # we use a regexp to match the marker that divides the various entries and sections
    re_marker           = re.compile("^--([a-z0-9]{8})-([A-Z])--$")

    re_general_info     = re.compile("^\[(.*)\] (.*) (.*) (\d*) (.*) (\d*)$")

    for l in f:

        match = re_marker.match(l)

        # handle the change of entry and section
        if (match != None):
            print("change! new entry: " + match.group(1) + " section: " + match.group(2))
            current_entry    = match.group(1)
            current_section  = match.group(2)

            if (current_section == "A"):
                current_section = "general_info"
            elif (current_section == "B"):
                current_section = "request_headers"
            elif (current_section == "B"):
                current_section = "request_body"
            elif (current_section == "F"):
                current_section = "response_headers"
            elif (current_section == "E"):
                current_section = "response_body"
            elif (current_section == "H"):
                current_section = "modsec_info"
            continue
        
        # makes space for the new entry if needed
        if (not current_entry in entries):
            entries[current_entry] = {}

        # makes space for the new section if needed
        if (not current_section in entries[current_entry]):
            entries[current_entry][current_section] = []

        # Handling section A - general info 
        # this is usually just one line with all the info we need
        if (current_section == "general_info"):
            m = re_general_info.match(l)

            if (m != None):
                data = {}
                data['time']        = m.group(1)
                data['uniqid']      = m.group(2)
                data['client_ip']   = m.group(3)
                data['size']        = m.group(4)
                data['server_ip']   = m.group(5)
                data['server_port'] = m.group(6)
                print("appending")
                entries[current_entry][current_section].append(data)

    f.close()
    print(entries)

if __name__ == "__main__":
    sys.exit(main(get_options()))