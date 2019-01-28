# modsec-parse
[Modsecurity](https://modsecurity.org/) is a powerful web application firewall, but its log format is quite difficult to quickly parse to check for specific things or to get an eagle eye of what's going on.

This tool aims to simplify CLI access to modsecurity logs to quickly respond to reports and get a better understaning of what's going on.

This tool is really (really!) young, probably there's something better around but I couldn't find it.

*NOTE*: you need to run it as a user that can read `INPUT_LOG_FILE`

## usage
```
modsec-parse.py [-h] [-c] [-i INPUT_LOG_FILE] [-gu GREP] [-m METHOD] [-reqb STRING]  [-resb STRING] [-sd STARTDATE]  [-sd ENDDATE]  [-id ID] [-cip CLIENT_IP] [-o perurl|fulldump]  [-of LIST]
```

* `-h` show help

* `-c` collects data from all the files int the same directory of `INPUT_LOG_FILE` and with a name containing `INPUT_LOG_FILE`

* `-i INPUT_LOG_FILE` reads data from `INPUT_LOG_FILE` (default: `modsec_audit.log`)

* `-gu GREP` keep all entries with URL matching `GREP`

* `-m METHOD` keep all entries with requests using `METHOD`

* `-reqb STRING` keep all entries with request body matching `STRING`

* `-resb STRING` keep all entries with response body matching `STRING`

* `-sd STARTDATE` keep all entries after `STARTDATE` in DD/MM/YYYY format
  
* `-ed ENDDATE` keep all entries before `ENDDATE` in DD/MM/YYYY format

* `-id ID` show only the entry with the id in section A matching `ID`

* `-cip CLIENT_IP` show only entries related to client `CLIENT_IP`
                        
* `-o FORMAT` choose what to display, supported `FORMAT`:
	* `perurl` prints out the ids of the offending rules and how many times they happen per URL

	* `fulldump` prints out the whole data structure created for each entry, mainly for debug purposes
* `-of LIST` if no `-o FORMAT` is specified, each entry will be displayed showing the fields listed in the comma separated `LIST`. Available fields are:
	* `id` the entry unique id
	* `mtd` the request method
	* `url` the request URL
	* `time` the request time
	* `ip` the client IP address
	* `rule` the violated rule, with id and message where available

	the default `LIST` is: `id,mtd,url,time,ip,rule`