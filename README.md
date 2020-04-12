# AWS WAF classic to AWS WAF
- Status : Alpha testing
Migrates regional webacl from classic WAF to WAFv2.



## Instructions to setup and run
- Configure aws cli
```
aws configure
```
- Run 
```
python3 wafer.py
```
## Goals Achieved
 - Creates a json file from calssic WAF that can be used to apply updates to WAFv2
 - Creates a copy of IP sets and regex pattern sets from classic WAF 
 - Creates a Web ACL in WAFv2
 - Identifies and associates resources from classic WAF to the new WAF (Both loadbalancers and API gateways) 

## To Do
- Port to boto3
- Delete classic waf
- Add command line args
- Code optimization
- Regional and non regional as arguments

## Things I'm not thinking about just yet but might in the future
- Support for migrating it from one account to another.
- Adding managed rules (cost optimization)
- pass aws cli 1/2 as command line argument

