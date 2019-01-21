import argparse
import sys
import re
import ModsecParser
import pprint
import os
from datetime import datetime

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
        '-c',
        '--continuous',
        help="""tries to join earlier logs if found (searches for files with name like INPUT_LOG_FILE-yyyymmdd)""",
        action='store_true')
    cmd_parser.add_argument(
        '-gu',
        '--grep',
        help="""show all entries with URL matching the given string""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-resb',
        '--resbody',
        help="""show all entries with response body matching the given string""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-reqb',
        '--reqbody',
        help="""show all entries with request body matching the given string""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-m',
        '--method',
        help="""show all entries with requests using the given method""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-sd',
        '--startdate',
        help="""show all entries after DD/MM/YYYY""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-ed',
        '--enddate',
        help="""show all entries before DD/MM/YYYY""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-id',
        '--id',
        help="""show only entries with the id in section A matching ID""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-o',
        '--output',
        help="""select which kind of output to display, as of now these are the available options: perurl, fulldump""",
        type=str,
        default='')

    args = cmd_parser.parse_args(cmd_args)

    options = {}
    options['input_log_file'] = args.input_log_file
    options['grep']         = args.grep
    options['method']       = args.method
    options['output']       = args.output
    options['resbody']      = args.resbody
    options['reqbody']      = args.reqbody
    options['startdate']    = args.startdate
    options['enddate']      = args.enddate
    options['id']           = args.id
    options['continuous']   = args.continuous

    return options

def filterByMatchingURL(logs,s):
    entries = {}
    for e in logs:
        if (s in logs[e]['request']['url']):
            entries[e]  = logs[e]
    return entries

def filterByMatchingResBody(logs,s):
    entries = {}
    for e in logs:
        if (('body' in logs[e]['response']) and (s in logs[e]['response']['body'])):
            entries[e]  = logs[e]
    return entries

def filterByMatchingReqBody(logs,s):
    entries = {}
    for e in logs:
        if (('body' in logs[e]['request']) and (s in logs[e]['request']['body'])):
            entries[e]  = logs[e]
    return entries

def filterByMatchingMethod(logs,m):
    entries = {}
    for e in logs:
        if (m.upper() in logs[e]['request']['method'].upper()):
            entries[e]  = logs[e]
    return entries

def filterByMatchingDate(logs,start=None,end=None):
    entries = {}
    for e in logs:
        # FIXME: this ugliness down here removes the time offset because %z expression seems not to get it correctly
        this_time = datetime.strptime(logs[e]['general_info']['time'].split(" ")[0],"%d/%b/%Y:%H:%M:%S")
        
        if ((not start is None) and (not end is None)):
            if ((this_time > start) and (this_time < end)):
                entries[e]  = logs[e]
        elif ((not end is None) and (this_time < end)):
            entries[e]  = logs[e]
        elif ((not start is None) and (this_time > start)):
            entries[e]  = logs[e]
    return entries

def filterByMatchingId(logs,search_id):
    entries = {}
    for e in logs:
        if (e == search_id):
            entries[e] = logs[e]
    return entries

def main(opts):

    if (opts['continuous']):
    	base_dir = os.path.dirname(os.path.abspath(opts['input_log_file']))
    	base_name= os.path.basename(opts['input_log_file'])
    	
    	base_dir_files = os.listdir(base_dir)

    	# we take only the files witch matching name
    	good_files = list(filter(lambda x: base_name in x,base_dir_files))

    	log = {}
    	for gf in good_files:
    		file_name = base_dir + "/" + gf
    		f = open(file_name,"r")
    		log.update(ModsecParser.parseFile(f))
    		f.close()
    	print("collected data from " + str(len(good_files)) + " in " + base_dir + " matching " + base_name)
    else:
    	f = open(opts['input_log_file'],"r")
    	log = ModsecParser.parseFile(f)
    	f.close()

    print(str(len(log)) + " entries found, filtering...")
    
    if (opts['id'] != ""):
        log = filterByMatchingId(log,opts['id'])

    if (opts['grep'] != ""):
        log = filterByMatchingURL(log,opts['grep'])

    if (opts['method'] != ""):
        log = filterByMatchingMethod(log,opts['method'])

    if (opts['reqbody'] != ""):
        log = filterByMatchingReqBody(log,opts['reqbody'])

    if (opts['resbody'] != ""):
        log = filterByMatchingResBody(log,opts['resbody'])

    if (opts['startdate'] != ""):
        opts['startdate'] = datetime.strptime(opts['startdate'] + ":00:00:00","%d/%m/%Y:%H:%M:%S")
    else:
        opts['startdate'] = None

    if (opts['enddate'] != ""):
        opts['enddate'] = datetime.strptime(opts['enddate'] + ":23:59:59","%d/%m/%Y:%H:%M:%S")
    else:
        opts['enddate'] = None

    if ((opts['startdate'] != None) or (opts['enddate'] != None)):
        log = filterByMatchingDate(log,opts['startdate'],opts['enddate'])

    # Nothing found, bye
    if (len(log) == 0):
    	print("\nNo matching entry found")
    	sys.exit(0)
    else:
    	print("\n--- RESULTS")

    # sorting things here because we will have less things to sort
    sorted_logs = sorted(log.iteritems(),key=lambda (k,v): (v['general_info']['time'],k))

    # output
    if (opts['output'] == "perurl"):
        r = {}
        for e in sorted_logs:
            p = e[1]['request']['method'] + " "+ e[1]['request']['url']
            if (not p in r):
                r[p] = {}
            
            if ('rule_id' in e[1]['modsec_info']):
            	if ('msg' in e[1]['modsec_info']):
                	rule_string = e[1]['modsec_info']['rule_id'] + " " + e[1]['modsec_info']['msg']
                else:
                	rule_string = e[1]['modsec_info']['rule_id']

                if (not rule_string in r[p]):
                    r[p][rule_string] = 1
                else:
                    r[p][rule_string] += 1
            else:
                if (not "xxxxxx violation without rule id" in r[p]):
                    r[p]['xxxxxx violation without rule id'] = 1
                else:
                    r[p]['xxxxxx violation without rule id'] += 1

        for e in r:
            print("\n" + e)
            for i in r[e]:
                print("\t" + i + " ( " + str(r[e][i]) + " times )")
    # fulldump output used mainly for debugging of single rules
    # selected with -id
    elif (opts['output'] == "fulldump"):
        pp = pprint.PrettyPrinter(indent=1)

        for e in sorted_logs:
            print pp.pprint(e[1])
            print "\n---\n"
    else:
        for e in sorted_logs:
            
            print("\n" + e[1]['general_info']['uniqid'] + "\t" + e[1]['request']['method'] + "\t" + e[1]['request']['url'] + "\t" + e[1]['general_info']['time'])
            
            if ('rule_id' in e[1]['modsec_info']):
            	# if we have a description we print it out
            	if ('msg' in e[1]['modsec_info']):
                	print("\t\t\t\t" + e[1]['modsec_info']['rule_id'] + "\t" + e[1]['modsec_info']['msg'])
                else:
                	print("\t\t\t\t" + e[1]['modsec_info']['rule_id'])
            
            elif ('Apache-Error' in e[1]['modsec_info']):
                print("\t\t\t\t" + e[1]['modsec_info']['Apache-Error'])
            
            else:
                print("\t" + str(e[1]['modsec_info']))

if __name__ == "__main__":
    sys.exit(main(get_options()))