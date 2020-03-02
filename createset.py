import json
import subprocess as sp


global region

# creates regex patternset
def create_regex_patterset(RegexPatternSetId):
    pattern_set = json.loads(sp.getoutput("aws waf-regional get-regex-pattern-set --regex-pattern-set-id "+ RegexPatternSetId))
    pattern_set = pattern_set['RegexPatternSet']
    pattern_list = []
    for regex in pattern_set['RegexPatternStrings']:
        pattern_list.append({"RegexString" : regex})
    try:
        create = sp.getoutput("aws wafv2 create-regex-pattern-set --name " + pattern_set["Name"] + "set --scope REGIONAL --region "+region+" --regular-expression-list ' " +json.dumps(pattern_list)+"'")
    except:
        print("RegexPatternSet creation failed, check if you have the permissions to create RegexPatternSet or if a RegexPatternSet by the name '"+pattern_set['Name']+"' already exists. (If yes delete and try again)")
    arn = json.loads(create)
    arn = arn["Summary"]["ARN"]
    # arn = "regexarn"
    return arn

# Creates a new IP set 
def create_ipset(ipsetid):
    ip_set = json.loads(sp.getoutput("aws waf-regional get-ip-set --ip-set-id "+ ipsetid))
    ip_set = ip_set['IPSet']
    ipv4set = str()
    ipv6set = str()
    arn =list()
    for ip  in ip_set['IPSetDescriptors']:
        if(ip['Type'] == "IPV4"):
            ipv4set = ipv4set + " " + ip["Value"]
        elif (ip["Type"] == "IPV6"):
            ipv6set = ipv6set + " " + ip["Value"]
    if(ipv4set != ""):
        try:
            create = json.loads(sp.getoutput("aws wafv2 create-ip-set --name "+ ip_set['Name'] +"ipv4set --scope REGIONAL --region "+region+" --ip-address-version IPV4 --addresses %s" %(ipv4set)))
            create = create["Summary"]
            arn.append(create["ARN"])
        except:
            print("IPset creation failed, check if you have the permissions to create IPsets or if an IPset by the name '"+ip_set['Name']+"ipv4set' already exists. (If yes delete and try again)")
        # arn=["ipv4arn"]
    elif(ipv6set != ""):
        try:
            create = json.loads(sp.getoutput("aws wafv2 create-ip-set --name "+ ip_set['Name'] +"ipv6set --scope REGIONAL --region "+region+" --ip-address-version IPV6 --addresses %s" %(ipv6set)))
            create = create["Summary"]
            arn.append(create["ARN"])
        except:
            print("IPset creation failed, check if you have the permissions to create IPsets or if an IPset by the name '"+ip_set['Name']+"ipv6set' already exists. (If yes delete and try again)")
        # arn=["ipv6arn"]
    return arn