# AWS WAF classic to AWS WAF
- Status : INCOMPLETE
Now creates a json file using which a rule group can be created.

## Issues

- If a IP set alreday exists it crashes.
- If a IP set is reused then it tries to create it again and crashes.
- Rate based rules gives the error -
```
An error occurred (WAFInvalidParameterException) when calling the CreateRuleGroup operation: Error reason: A reference in your rule statement is not valid., field: RATE_BASED_STATEMENT, parameter: RateBasedStatement
```
- To create remove it from the json file and use the same to add it through the console

## To Do
- Modularise
	- Port to boto3
	- Unlink resourses from classic waf
	- link resources to new one
	- Delete classic waf
	- Add command line args
	- Run in main
	- Code optimization
## Things I'm not thinking about just yet but might in the future
	- Adding managed rules (cost optimization)
	- pass aws cli 1/2 as command line argument

