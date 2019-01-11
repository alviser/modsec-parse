import argparse
import sys
import re
import ModsecParser

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

    log = ModsecParser.parseFile(f)

    f.close()
    
    for e in log:
        if ('client_ip' in log[e]['modsec_info']):
            print("entry id: " + log[e]['general_info']['uniqid'] + "\tclient ip: " + log[e]['general_info']['client_ip'] + "\tmodsec ip: " + log[e]['modsec_info']['client_ip'])

if __name__ == "__main__":
    sys.exit(main(get_options()))