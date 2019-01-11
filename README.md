# modsec-parse
This aims to be a simple command line tool to better read mod security logs.

This tool is really (really!) young, probably there's somthing better around but I couldn't find it.

## usage
```
modsec-parse.py [-h] [-i INPUT_LOG_FILE] [-g GREP] [-m METHOD]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_LOG_FILE, --input_log_file INPUT_LOG_FILE
                        a text file where each line holds a different URL
                        where to search for WP (default: modsec_audit.log)
  -g GREP, --grep GREP  show all entries with URL matching the given string
                        (default: )
  -m METHOD, --method METHOD
                        show all entries with requests using the given method
                        (default: )
```