import os 
import json 
import rulematch
import ratebased
import subprocess as sp
import associate_rescource

def removespace(name):
    temp =  ''.join(name.split(" "))
    return 'And'.join(name.split("&"))

val  = json.loads(os.popen('aws waf-regional list-web-acls').read())
for acl in val['WebACLs']:
    acl_id = acl['WebACLId']
    acl_desc = json.loads(os.popen('aws waf-regional get-web-acl --web-acl-id %s' %(acl_id)).read())['WebACL']
    def_action = acl_desc['DefaultAction']['Type']
    name = removespace(acl_desc['Name'])+'Rule'
    visibilityconfig = "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="+name+"METRICS"
    region = "ap-south-1"
    scope = "REGIONAL"
    rules = list()
    for r in acl_desc['Rules']:

        if(r["Type"] == "RATE_BASED"):
            newrule = ratebased.rulebuilder(r)
            rules.append(newrule)
        else:
            newrule = rulematch.rule_match(r)
            if newrule["Statement"] == {} :
                continue
            rules.append(newrule)
    print("Generated Json file for creating the group - ")
    rules = json.dumps(rules)
    print(rules)
    f = open("rulegroup.json","w")
    f.write(rules)
    f.close()
    print("Please run the following command -")
    # For some reason this refuses to run from here
    command  = "./create_web_acl.sh %s %s" %(name,visibilityconfig)
    print(command)
    #aclv2 = json.loads(os.popen(command).read())
    #aclv2 = aclv2["Summary"]["ARN"]
    aclv2 = input("Enter ARN of the new Web ACL :")
    arns = associate_rescource.get_rescource_list("2c659f1c-8f9b-40fd-834a-89961e7895eb")
    associate_rescource.disassociate_rescource(arns=arns)
    associate_rescource.associate_wafv2(arns= arns, webaclarn=aclv2)