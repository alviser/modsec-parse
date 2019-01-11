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
    cmd_parser.add_argument(
        '-g',
        '--grep',
        help="""show all entries with URL matching the given string""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-m',
        '--method',
        help="""show all entries with requests using the given method""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-o',
        '--output',
        help="""select which kind of output to display, as of now these are the available options: ruleids""",
        type=str,
        default='')

    args = cmd_parser.parse_args(cmd_args)

    options = {}
    options['input_log_file'] = args.input_log_file
    options['grep'] = args.grep
    options['method'] = args.method
    options['output'] = args.output

    return options

def filterByMatchingURL(logs,s):
    entries = {}
    for e in logs:
        if (s in logs[e]['request']['url']):
            entries[e]  = logs[e]
    return entries

def filterByMatchingMethod(logs,m):
    entries = {}
    for e in logs:
        if (m.upper() in logs[e]['request']['method'].upper()):
            entries[e]  = logs[e]
    return entries

def main(opts):

    f = open(opts['input_log_file'],"r")
    log = ModsecParser.parseFile(f)
    f.close()
    
    if (opts['grep'] != ""):
        log = filterByMatchingURL(log,opts['grep'])

    if (opts['method'] != ""):
        log = filterByMatchingMethod(log,opts['method'])

    # output
    if (opts['output'] == "ruleids"):
        r = {}
        for e in log:
            p = log[e]['request']['method'] + " "+ log[e]['request']['url']
            if (not p in r):
                r[p] = {}
            
            if ('rule_id' in log[e]['modsec_info']):
                if (not log[e]['modsec_info']['rule_id'] in r[p]):
                    r[p][log[e]['modsec_info']['rule_id']] = 1
                else:
                    r[p][log[e]['modsec_info']['rule_id']] += 1
            else:
                if (not "violation without rule id" in r[p]):
                    r[p]['violation without rule id'] = 1
                else:
                    r[p]['violation without rule id'] += 1

        for e in r:
            print("\n" + e)
            for i in r[e]:
                print(" " + i + " ( " + str(r[e][i]) + " times )")
    else:
        for e in log:
            print("\n" + log[e]['request']['method'] + "\t" + log[e]['request']['url'])
            if (('rule_id' in log[e]['modsec_info']) and ('msg' in log[e]['modsec_info'])):
                print(" " + log[e]['modsec_info']['rule_id'] + "\t" + log[e]['modsec_info']['msg'])
            elif ('Apache-Error' in log[e]['modsec_info']):
                print(" " + log[e]['modsec_info']['Apache-Error'])
            else:
                print(" " + str(log[e]['modsec_info']))

if __name__ == "__main__":
    sys.exit(main(get_options()))