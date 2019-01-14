import re

# parseFile(f)
# f     a file handler resulting from open(filename,"r")
#
# returns an entries structure which is a dict with each entry unique id as key, and each entry has:
#
# ['general_info']
#   ['time']       
#   ['uniqid']     
#   ['client_ip']  
#   ['size']       
#   ['server_ip']  
#   ['server_port']
# ['request']
#   ['method']  
#   ['url']     
#   ['protocol']
#   ['headers']
#       [<headername>]*     one or more header,value pair
#   ['body']
# ['response']
#   ['status']  
#   ['message']     
#   ['protocol']
#   ['headers']
#       [<headername>]*     one or more header,value pair
#   ['body']
# ['modsec_info']
#   ['rule_id']             if present is retrieved from the "Apache-Error: ..." row
#   ['msg']                 if present is retrieved from the "Apache-Error: ..." row
#   ['client_ip']           if present is retrieved from the "Apache-Error: ..." row
#   ['file']                if present is retrieved from the "Apache-Error: ..." row
#   ['verbose']             if present is retrieved from the "Apache-Error: ..." row
#   [<headername>]*         one entry for each <name>: <value> row in the H section (possibily replicating some other keys in the "Apache-Error" valure

def parseFile(f):
    entries         = {}
    current_entry   = ""
    current_section = ""
    current_subsection = "" # this is used for internal organization and does not end in the final data structure

    # we use a regexp to match the marker that divides the various entries and sections
    re_marker           = re.compile("^--([a-z0-9]{8})-([A-Z])--$")

    # section A - regexp for the general informations line
    re_general_info     = re.compile("^\[(.*)\] (.*) (.*) (\d*) (.*) (\d*)$")

    # section B - regexp for the method/URL/Protocol line, the rest are just headers
    re_request          = re.compile("^([A-Z]*) (.*) (.*)$")

    # section F - regexp for the Protocol/Status/Message line, the rest are just headers
    re_response         = re.compile("^(.*) (\d*) (.*)$")

    # section H - regexp for modsec info
    # these are searched in the Apache-Error line
    re_modsec_info_rule_id = re.compile(" \[id \"(\d*)\"\] ")
    re_modsec_info_msg     = re.compile(" \[msg \"(.*?)\"\] ")
    re_modsec_info_client  = re.compile(" \[client (.*?)\] ")
    re_modsec_info_file    = re.compile(" \[file \"(.*?)\"\] ")
    re_modsec_verbose      = re.compile("\] ModSecurity: (.*) \[file")

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
                current_subsection = "body"
            elif (current_section == "H"):
                current_section = "modsec_info"
            elif (current_section == "Z"):
                current_section = "entry_finished"
            else:
                print("UNKNOWN SECTION IDENTIFIER: " + current_section)
            continue
        
        # makes space for the new entry if needed
        if (not current_entry in entries):
            entries[current_entry] = {}

        # makes space for the new section if needed
        if (current_section != "entry_finished" and (not current_section in entries[current_entry])):
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

            if (m != None):
                entries[current_entry][current_section]['method']      = m.group(1)
                entries[current_entry][current_section]['url']         = m.group(2)
                entries[current_entry][current_section]['protocol']    = m.group(3)
            
            else:
                if (not "headers" in entries[current_entry][current_section]):
                    entries[current_entry][current_section]['headers']  = {}

                divider = l.find(":")
                # WARN: we collapse multiple headers with the same name, might it be a problem?
                if (l[:divider] != ""):
                    entries[current_entry][current_section]['headers'][l[:divider]] = l[divider+1:].strip()

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

        # Handling section F - response headers
        if (current_section == "response" and current_subsection == "headers"):
            m = re_response.match(l)

            if (m != None):
                entries[current_entry][current_section]['protocol'] = m.group(1)
                entries[current_entry][current_section]['status']   = m.group(2)
                entries[current_entry][current_section]['message']  = m.group(3)
            
            else:
                if (not "headers" in entries[current_entry][current_section]):
                    entries[current_entry][current_section]['headers']  = {}

                divider = l.find(":")
                # WARN: we collapse multiple headers with the same name, might it be a problem?
                if (l[:divider] != ""):
                    entries[current_entry][current_section]['headers'][l[:divider]] = l[divider+1:].strip()

            # skip the rest of the checks as we certainly are not in the other sections
            # this should make things faster, but might break something: CHECK IT OUT!
            continue

        # Handling section E - response body
        # NOTE: if there is no response body the 'body' key won't be even created
        if (current_section == "response" and current_subsection == "body"):
            if (not "body" in entries[current_entry][current_section]):
                    entries[current_entry][current_section]['body']  = ""
            
            entries[current_entry][current_section]['body'] += l

            # skip the rest of the checks as we certainly are not in the other sections
            # this should make things faster, but might break something: CHECK IT OUT!
            continue

        if (current_section == "modsec_info"):
            divider = l.find(":")
            # WARN: we collapse multiple headers with the same name, might it be a problem?
            if (l[:divider] != ""):
                entries[current_entry][current_section][l[:divider]] = l[divider+1:].strip()

            if (l[:divider] == "Apache-Error"):
                value = l[divider+1:].strip()
                
                m = re_modsec_info_rule_id.search(value)
                if (m != None):
                    entries[current_entry][current_section]['rule_id'] = m.group(1)

                m = re_modsec_info_msg.search(value)    
                if (m != None):
                    entries[current_entry][current_section]['msg'] = m.group(1)

                m = re_modsec_info_client.search(value) 
                if (m != None):
                    entries[current_entry][current_section]['client_ip'] = m.group(1)

                m = re_modsec_info_file.search(value)   
                if (m != None):
                    entries[current_entry][current_section]['file'] = m.group(1)

                m = re_modsec_verbose.search(value)     
                if (m != None):
                    entries[current_entry][current_section]['verbose'] = m.group(1)

    return entries
