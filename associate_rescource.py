import json 
import subprocess as sp
import os

def get_rescource_list(rule_id):
    loadbalancers = json.loads(sp.getoutput('aws elbv2 describe-load-balancers'))
    loadbalancers = loadbalancers["LoadBalancers"]
    lbs =list()
    for lb in loadbalancers:
        try:
            acl = json.loads(sp.getoutput(('aws waf-regional get-web-acl-for-resource --resource-arn %s' %(lb["LoadBalancerArn"]))))
            if(acl["WebACLSummary"]["WebACLId"] == rule_id):
                print("Found Loadbalancer : " +lb["LoadBalancerName"])
                print("associated with rule : " + rule_id)
                lbs.append(lb["LoadBalancerArns"])
        except:
            continue
    return lbs

def associate_wafv2(arns, webaclarn):
    for arn in arns:
        print("Adding to new Acl : " + arn)
        os.system("aws wafv2 associate-web-acl --web-acl-arn %s --resource-arn %s" %(webaclarn,arn))
    return 

def disassociate_rescource(arns):
    for arn in arns:
        print("Removing lb from waf classic : "+arn)
        os.system("aws waf-regional disassociate-web-acl --resource-arn %s" %(arn))
    return
# get_rescource_list("2c659f1c-8f9b-40fd-834a-89961e7895eb")