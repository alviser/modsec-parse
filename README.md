# modsec-parse
This aims to be a simple command line tool to better read mod security logs.

This tool is really (really!) young, probably there's somthing better around but I couldn't find it.

*NOTE*: you need to run it as a user that can read `INPUT_LOG_FILE`

## usage
```
modsec-parse.py [-h] [-i INPUT_LOG_FILE] [-g GREP] [-m METHOD] [-r STRING] [-b STRING] [-o ruleids]
```

* -h show help

* -i INPUT_LOG_FILE reads data from `INPUT_LOG_FILE` (default: `modsec_audit.log`)

* -g GREP keep all entries with URL matching `GREP`

* -m METHOD keep all entries with requests using `METHOD`

* -r STRING keep all entries with request body matching `STRING`

* -b STRING keep all entries with response body matching `STRING`

* -o ruleids choose what to display, as of now only `ruleids` is supported
	* `ruleids` prints out the ids of the offending rules and how many times they happen per URL