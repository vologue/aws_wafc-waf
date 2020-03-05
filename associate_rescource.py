import json 
import subprocess as sp
import os
import createset
import time ,sys
def get_apigateway_arns():
    arns =list()
    tentative_arn = "arn:aws:apigateway:"+createset.region+"::/restapis/"
    #tentative_arn = "arn:aws:apigateway:ap-south-1::/restapis/"
    
    try:
        restapis = json.loads(sp.getoutput("aws apigateway get-rest-apis"))
        restapis = restapis["items"]
    except :
        print("No Api gateways in the region: " + createset.region)
        
        return []
    for api in restapis:
        api_id = api["id"]
        try :
            stages = json.loads(sp.getoutput("aws apigateway  get-stages --rest-api-id "+ api_id ))
            stages = stages["item"]

        except:
            print("No stage for the api : "+ api["name"])
            continue
        for stage in stages:
            stage_name = stage["stageName"]
            arn = tentative_arn + api_id + "/stages/" + stage_name
            arns.append(arn)
    return arns

def get_rescource_list(rule_id):
    try:
        loadbalancers = json.loads(sp.getoutput('aws elbv2 describe-load-balancers'))
        loadbalancers = loadbalancers["LoadBalancers"]
    except:
        print("No loadbalancers found")
        return []
    arn_list = list()
    for lb in loadbalancers:
        try:
            acl = json.loads(sp.getoutput(('aws waf-regional get-web-acl-for-resource --resource-arn %s' %(lb["LoadBalancerArn"]))))
            if(acl["WebACLSummary"]["WebACLId"] == rule_id):
                print("Found Loadbalancer : " +lb["LoadBalancerName"])
                print("associated with rule : " + rule_id)
                arn_list.append(lb["LoadBalancerArn"])
        except:
            continue
    
    gateways = get_apigateway_arns()
    for arn in gateways:
        try:
            acl = json.loads(sp.getoutput(('aws waf-regional get-web-acl-for-resource --resource-arn %s' %(arn))))
            if(acl["WebACLSummary"]["WebACLId"] == rule_id):
                print("Found apigateway : " + arn)
                print("associated with rule : " + rule_id)
                arn_list.append(arn)
        except:
            print("No web acl linked with the api " + arn)
            continue
    return arn_list

def associate_wafv2(arns, webaclarn):
    print("Waiting for disassociation to take affect (10s)")
    # for i in range(20):
    #     print("\r{} seconds left".format(20 - i), end='')
    #     time.sleep(1)
    for arn in arns:
        print("Adding to new Acl : " + arn)
        command = "aws wafv2 associate-web-acl --web-acl-arn %s --resource-arn %s" %(webaclarn,arn)
        out = "An error occurred (WAFUnavailableEntityException) when calling the AssociateWebACL operation: AWS WAF couldn’t retrieve the resource that you requested. Retry your request."
        i = 1
        print("Trying command : " + command)
        while("error" in out):
            print("\rTrial : {}".format(i),end = '')
            out = str(sp.getoutput(command))
            time.sleep(1)
            i =i +1
        print("\nAdded successfully")
    return 

def disassociate_rescource(arns):
    for arn in arns:
        print("Removing lb from waf classic : "+arn)
        os.system("aws waf-regional disassociate-web-acl --resource-arn %s" %(arn))
    return

# print(get_rescource_list("2c659f1c-8f9b-40fd-834a-89961e7895eb"))