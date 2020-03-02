# AWS WAF classic to AWS WAF
- Status : INCOMPLETE
Migrates regional webacl from classic WAF to WAFv2.

## Issues

- If a IP set already exists it crashes.
- If a IP set is reused then it tries to create it again and crashes.
- Works for only regional waf


## Instructions to setup and run

- Run 
```
python3 waf-clssic-to-associate.py
```


## To Do
- Modularise
	- Port to boto3
	- Delete classic waf
	- Add command line args
	- Run in main
	- Handle already existing IPsets
	- Code optimization
	- Regional and non regional as arguments
	- Link API gateways to stuff

## Things I'm not thinking about just yet but might in the future
	- Adding managed rules (cost optimization)
	- pass aws cli 1/2 as command line argument

