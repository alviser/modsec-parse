# modsec-parse
This aims to be a simple command line tool to better read mod security logs.

This tool is really (really!) young, probably there's somthing better around but I couldn't find it.

## usage
```
modsec-parse.py [-h] [-i INPUT_LOG_FILE] [-g GREP] [-m METHOD] [-o ruleids]
```

* -i INPUT_LOG_FILE reads data from `INPUT_LOG_FILE` (default: `modsec_audit.log`)

* -g GREP keep all entries with URL matching `GREP`

* -m METHOD keep all entries with requests using `METHOD`

* -o ruleids choose what to display, as of now only `ruleids` is supported
	* `ruleids` prints out the ids of the offending rules and how many times they happen per URL