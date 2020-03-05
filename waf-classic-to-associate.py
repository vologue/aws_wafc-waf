import os 
import json 
import rulematch
import ratebased
import subprocess as sp
import associate_rescource
import createset


def main():
    val  = json.loads(os.popen('aws waf-regional list-web-acls').read())
    for acl in val['WebACLs']:
        acl_id = acl['WebACLId']
        acl_desc = json.loads(os.popen('aws waf-regional get-web-acl --web-acl-id %s' %(acl_id)).read())['WebACL']
        # print(acl_desc)
        def_action = acl_desc['DefaultAction']['Type'][0]+acl_desc['DefaultAction']['Type'][1:].lower()
        name = rulematch.make_regex_compliant(acl_desc['Name'])+'Rule'
        visibilityconfig = "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="+name+"METRICS"
        # print(acl_desc["WebACLArn"])
        createset.region = acl_desc["WebACLArn"].split(':')[-3]
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
        # print(rules)
        f = open("rulegroup.json","w")
        f.write(rules)
        f.close()
        print("Creating New webacl -")
        command  = "aws wafv2 create-web-acl --name %s --scope REGIONAL --default-action %s={} --rules file://rulegroup.json --visibility-config %s --region %s" %(name,def_action,visibilityconfig,createset.region)
        #print(command)
        aclv2 = json.loads(os.popen(command).read())
        aclv2 = aclv2["Summary"]["ARN"]
        arns = associate_rescource.get_rescource_list("2c659f1c-8f9b-40fd-834a-89961e7895eb")
        associate_rescource.disassociate_rescource(arns=arns)
        associate_rescource.associate_wafv2(arns= arns, webaclarn=aclv2)

if __name__ == "__main__":
    main()