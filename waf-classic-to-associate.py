import os 
import json 
import rulematch
import ratebased
import subprocess as sp
import boto3

client = boto3.client('wafv2')
def removespace(name):
    temp =  ''.join(name.split(" "))
    return 'And'.join(name.split("&"))

val  = json.loads(os.popen('aws waf list-web-acls').read())
for acl in val['WebACLs']:
    acl_id = acl['WebACLId']
    acl_desc = json.loads(os.popen('aws waf get-web-acl --web-acl-id %s' %(acl_id)).read())['WebACL']
    def_action = acl_desc['DefaultAction']['Type']
    name = removespace(acl_desc['Name'])+'RuleGroup'
    visibilityconfig = "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="+name+"METRICS"
    region = "ap-south-1"
    scope = "REGIONAL"
    rules = list()
    for r in acl_desc['Rules']:

        if(r["Type"] == "RATE_BASED"):
            newrule = ratebased.rulebuilder(r)
            if newrule["Statement"] == {} :
                continue
            rules.append(newrule)
        else:
            newrule = rulematch.rule_match(r)
            if newrule["Statement"] == {} :
                continue
            rules.append(newrule)
    print("Generated Json file for creating the group - ")
    rules = json.dumps(rules)
    f = open("rulegroup.json","w")
    f.write(rules)
    print("Please run the following command -")
    # For some reason this refuses to run from here
    command  = "./creategroup.sh %s %s" %(name,visibilityconfig)
    print(command)