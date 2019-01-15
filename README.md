# modsec-parse
This aims to be a simple command line tool to better read mod security logs.

This tool is really (really!) young, probably there's something better around but I couldn't find it.

*NOTE*: you need to run it as a user that can read `INPUT_LOG_FILE`

## usage
```
modsec-parse.py [-h] [-i INPUT_LOG_FILE] [-g GREP] [-m METHOD] [-r STRING] [-b STRING] [-o ruleids]
```

* -h show help

* -i INPUT_LOG_FILE reads data from `INPUT_LOG_FILE` (default: `modsec_audit.log`)

* -gu GREP keep all entries with URL matching `GREP`

* -m METHOD keep all entries with requests using `METHOD`

* -reqb STRING keep all entries with request body matching `STRING`

* -resb STRING keep all entries with response body matching `STRING`

* -sd STARTDATE keep all entries after `STARTDATE` in DD/MM/YYYY format
  
* -ed ENDDATE keep all entries before `ENDDATE` in DD/MM/YYYY format

* -id ID show only the entry with the id in section A matching `ID`
                        
* -o FORMAT choose what to display, supported `FORMAT`:
	* `perurl` prints out the ids of the offending rules and how many times they happen per URL

	* `fulldump` prints out the whole data structure created for each entry, mainly for debug purposes
