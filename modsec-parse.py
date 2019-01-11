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
    current_subsection = ""     # this is used for internal organization and does not end in the final data structure

    # we use a regexp to match the marker that divides the various entries and sections
    re_marker           = re.compile("^--([a-z0-9]{8})-([A-Z])--$")

    # section A - regexp for the general informations line
    re_general_info     = re.compile("^\[(.*)\] (.*) (.*) (\d*) (.*) (\d*)$")

    # section B - regexp for the method/URL/Protocol line, the rest are just headers
    re_request          = re.compile("^([A-Z]*) (.*) (.*)$")

    for l in f:
        # skip empty lines
        if (l == ""):
            continue

        match = re_marker.match(l)

        # handle the change of entry and section
        if (match != None):
            # print("change! new entry: " + match.group(1) + " section: " + match.group(2))
            current_entry    = match.group(1)
            current_section  = match.group(2)

            if (current_section == "A"):
                current_section = "general_info"
            elif (current_section == "B"):
                current_section = "request"
                current_subsection = "headers"
            elif (current_section == "C"):
                current_section = "request"
                current_subsection = "body"
            elif (current_section == "F"):
                current_section = "response"
                current_subsection = "headers"
            elif (current_section == "E"):
                current_section = "response"
                current_subsection = "headers"
            elif (current_section == "H"):
                current_section = "modsec_info"
            continue
        
        # makes space for the new entry if needed
        if (not current_entry in entries):
            entries[current_entry] = {}

        # makes space for the new section if needed
        if (not current_section in entries[current_entry]):
            entries[current_entry][current_section] = {}

        # Handling section A - general info 
        # this is usually just one line with all the info we need
        if (current_section == "general_info"):
            m = re_general_info.match(l)

            if (m != None):
                entries[current_entry][current_section]['time']        = m.group(1)
                entries[current_entry][current_section]['uniqid']      = m.group(2)
                entries[current_entry][current_section]['client_ip']   = m.group(3)
                entries[current_entry][current_section]['size']        = m.group(4)
                entries[current_entry][current_section]['server_ip']   = m.group(5)
                entries[current_entry][current_section]['server_port'] = m.group(6)

            # skip the rest of the checks as we certainly are not in the other sections
            # this should make things faster, but might break something: CHECK IT OUT!
            continue

        # Handling section B - request headers
        if (current_section == "request" and current_subsection == "headers"):
            m = re_request.match(l)
            data = {}

            if (m != None):
                entries[current_entry][current_section]['method']      = m.group(1)
                entries[current_entry][current_section]['url']         = m.group(2)
                entries[current_entry][current_section]['protocol']    = m.group(3)
            
            else:
                if (not "headers" in entries[current_entry][current_section]):
                    entries[current_entry][current_section]['headers']  = {}

                divider = l.find(":")
                # WARN: we collapse multiple headers with the same name, might it be a problem?
                entries[current_entry][current_section]['headers'][l[:divider]] = l[divider:]

            # skip the rest of the checks as we certainly are not in the other sections
            # this should make things faster, but might break something: CHECK IT OUT!
            continue

        # Handling section C - request body
        # NOTE: if there is no request body the 'body' key won't be even created
        if (current_section == "request" and current_subsection == "body"):
            if (not "body" in entries[current_entry][current_section]):
                    entries[current_entry][current_section]['body']  = ""
            
            entries[current_entry][current_section]['body'] += l

            # skip the rest of the checks as we certainly are not in the other sections
            # this should make things faster, but might break something: CHECK IT OUT!
            continue


    f.close()
    print(entries)

if __name__ == "__main__":
    sys.exit(main(get_options()))