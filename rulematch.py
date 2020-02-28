import os
import json
import subprocess as sp

#Handling whitespaces and '&' in the names
def removespace(name):
    temp =  ''.join(name.split(" "))
    return 'And'.join(temp.split("&"))

# Creates a new regex patternset
def create_regex_patterset(RegexPatternSetId):
    pattern_set = json.loads(sp.getoutput("aws waf-regional get-regex-pattern-set --regex-pattern-set-id "+ RegexPatternSetId))
    pattern_set = pattern_set['RegexPatternSet']
    pattern_list = []
    for regex in pattern_set['RegexPatternStrings']:
        pattern_list.append({"RegexString" : regex})
    create = sp.getoutput("aws wafv2 create-regex-pattern-set --name " + pattern_set["Name"] + "set --scope REGIONAL --region ap-south-1 --regular-expression-list ' " +json.dumps(pattern_list)+"'")
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
        create = json.loads(sp.getoutput("aws wafv2 create-ip-set --name "+ ip_set['Name'] +"ipv4set --scope REGIONAL --ip-address-version IPV4 --addresses %s" %(ipv4set)))
        create = create["Summary"]
        arn.append(create["ARN"])
        # arn=["ipv4arn"]
    elif(ipv6set != ""):
        create = json.loads(sp.getoutput("aws wafv2 create-ip-set --name "+ ip_set['Name'] +"ipv6set --scope REGIONAL --ip-address-version IPV6 --addresses %s" %(ipv6set)))
        create = create["Summary"]
        arn.append(create["ARN"])
        # arn=["ipv6arn"]
    return arn


# defines fields and text transformations
def match_fileds(old_state, i):
    statement = { "FieldToMatch": {
          
            },
            "TextTransformations": [

            ]
        }
    if old_state["FieldToMatch"]["Type"] == "HEADER":
        statement["FieldToMatch"]["SingleHeader"] = {
            "Name" : old_state["FieldToMatch"]["Data"]
        }
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
        
    elif old_state["FieldToMatch"]["Type"] == "SINGLE_QUERY_ARG":
        statement["FieldToMatch"]["SingleQueryArgument"] = {
            "Name" : old_state["FieldToMatch"]["Data"]
        }
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    elif old_state["FieldToMatch"]["Type"] == "ALL_QUERY_ARGS":
        statement["FieldToMatch"]["AllQueryArguments"] = {}
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    
    elif old_state["FieldToMatch"]["Type"] == "URI":
        statement["FieldToMatch"]["UriPath"] = {}
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    elif old_state["FieldToMatch"]["Type"] == "QUERY_STRING":
        statement["FieldToMatch"]["QueryString"] = {}
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    elif old_state["FieldToMatch"]["Type"] == "BODY":
        statement["FieldToMatch"]["Body"] = {}
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    elif old_state["FieldToMatch"]["Type"] == "METHOD":
        statement["FieldToMatch"]["Method"] = {}
        statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    return statement


# builds the statement 
def build_statement(predicate,num):
    statement =list()
    statementset = "OrStatement"
    if(predicate["Negated"] == True):
        statementset = "NotStatement"

    if (predicate["Type"] == "XssMatch"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-xss-match-set --xss-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['XssMatchSet']
        for state in range(len(old_statements["XssMatchTuples"])):
            statement.append({"XssMatchStatement" : match_fileds(old_state = old_statements["XssMatchTuples"][state],i = state)})
        if (len(old_statements["XssMatchTuples"])==1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {}}}
            temp[statementset]["Statement"] = statement[0]
            return temp
        elif len(old_statements["XssMatchTuples"])==1:
            return statement[0]
        elif (len(old_statements["XssMatchTuples"]) > 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement":{"Statements" : []}}}}
            temp[statementset]["Statement"]["AndStatement"]["Statements"] = statement
            return temp
        elif (len(old_statements["XssMatchTuples"]) >1):
            temp = {statementset : {"Statements" : []}}
            temp[statementset]["Statements"] = statement
            return temp
        else:
            return {}

    elif (predicate["Type"] == "SqlInjectionMatch"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-sql-injection-match-set --sql-injection-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['SqlInjectionMatchSet']
        for state in range(len(old_statements["SqlInjectionMatchTuples"])):
            statement.append({"SqliMatchStatement" : match_fileds(old_state = old_statements["SqlInjectionMatchTuples"][state],i = state)})
        if (len(old_statements["SqlInjectionMatchTuples"]) == 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {}}}
            temp[statementset]["Statement"] = statement[0]
            return temp
        elif len(old_statements["SqlInjectionMatchTuples"])==1:
            return statement[0]
        elif (len(old_statements["SqlInjectionMatchTuples"]) > 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement":{"Statements" : []}}}}
            temp[statementset]["Statement"]["AndStatement"]["Statements"] = statement
            return temp
        elif (len(old_statements["SqlInjectionMatchTuples"]) >1):
            temp = {statementset : {"Statements" : []}}
            temp[statementset]["Statements"] = statement
            return temp
        else:
            return {}


    elif (predicate["Type"] == "ByteMatch"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-byte-match-set --byte-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['ByteMatchSet']
        for state in range(len(old_statements["ByteMatchTuples"])):
            bytetuple = match_fileds(old_state = old_statements["ByteMatchTuples"][state],i = state)
            bytetuple['SearchString'] = old_statements["ByteMatchTuples"][state]['TargetString']
            bytetuple['PositionalConstraint'] = old_statements["ByteMatchTuples"][state]['PositionalConstraint']
            statement.append({"ByteMatchStatement" :  bytetuple})
        if (len(old_statements["ByteMatchTuples"]) == 1 and predicate["Negated"] == True) :
            temp = {statementset : {"Statement" : {}}}
            temp[statementset]["Statement"] = statement[0]
            return temp
        elif len(old_statements["ByteMatchTuples"])==1:
            return statement[0]
        elif (len(old_statements["ByteMatchTuples"]) > 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement":{"Statements" : []}}}}
            temp[statementset]["Statement"]["AndStatement"]["Statements"] = statement
            return temp
        elif (len(old_statements["ByteMatchTuples"]) >1):
            temp = {statementset : {"Statements" : []}}
            temp[statementset]["Statements"] = statement
            return temp
        else:
            return {}


    elif (predicate["Type"] == "SizeConstraint"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-size-constraint-set --size-constraint-set-id " + predicate["DataId"]))
        old_statements = old_statements['SizeConstraintSet']
        for state in range(len(old_statements["SizeConstraints"])):
            bytetuple = match_fileds(old_state = old_statements["SizeConstraints"][state],i = state)
            bytetuple['ComparisonOperator'] = old_statements["SizeConstraints"][state]['ComparisonOperator']
            bytetuple['Size'] = old_statements["SizeConstraints"][state]['Size']
            statement.append({"SizeConstraintStatement" :  bytetuple})
        
        if (len(old_statements["SizeConstraints"]) == 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {}}}
            temp[statementset]["Statement"] = statement[0]
            return temp
        elif len(old_statements["SizeConstraints"])==1:
            return statement[0]
        elif (len(old_statements["SizeConstraints"]) > 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement":{"Statements" : []}}}}
            temp[statementset]["Statement"]["AndStatement"]["Statements"] = statement
            return temp
        elif (len(old_statements["SizeConstraints"]) >1):
            temp = {statementset : {"Statements" : []}}
            temp[statementset]["Statements"] = statement
            return temp
        else:
            return {}

    
    elif (predicate["Type"] == "RegexMatch"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-regex-match-set --regex-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['RegexMatchSet']
        for state in range(len(old_statements["RegexMatchTuples"])):
            bytetuple = match_fileds(old_state = old_statements["RegexMatchTuples"][state],i = state)
            bytetuple['ARN'] = create_regex_patterset(old_statements["RegexMatchTuples"][state]['RegexPatternSetId'])
            statement.append({"RegexPatternSetReferenceStatement" :  bytetuple})

        if (len(old_statements["RegexMatchTuples"]) == 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {}}}
            temp[statementset]["Statement"] = statement[0]
            return temp
        elif len(old_statements["RegexMatchTuples"])==1:
            return statement[0]
        elif (len(old_statements["RegexMatchTuples"]) > 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement":{"Statements": []}}}}
            temp[statementset]["Statement"]["AndStatement"]["Statements"] = statement
            return temp
        elif (len(old_statements["RegexMatchTuples"]) >1):
            temp = {statementset : {"Statements" : []}}
            temp[statementset]["Statements"] = statement
            return temp
        else:
            return {}

    
    elif (predicate["Type"] == "IPMatch"):
        ARN = create_ipset(predicate["DataId"])

        if (len(ARN) == 1 and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {}}}
            for ipset in ARN:
                temp[statementset]["Statement"] = {"IPSetReferenceStatement" : {"ARN": ipset}}
            return temp
        elif len(ARN)==1:
            return {"IPSetReferenceStatement" : {"ARN": ARN[0]}}
        elif (len(ARN >1) and predicate["Negated"] == True):
            temp = {statementset : {"Statement" : {"AndStatement" : {"Statements" : []}}}}
            for ipset in ARN:
                temp[statementset]["Statement"]["AndStatement"]["Statements"].append({"IPSetReferenceStatement" : {"ARN": ipset}})
            return temp
        elif (len(ARN >1)):
            temp = {statementset : {"Statements" : []}}
            for ipset in ARN:
                temp[statementset]["Statements"].append({"IPSetReferenceStatement" : {"ARN": ipset}})

            return temp
        else:
            return {}

    elif (predicate["Type"] == "GeoMatch"):
        old_statements = json.loads(sp.getoutput("aws waf-regional get-geo-match-set --geo-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['GeoMatchSet']
        temp = {"GeoMatchStatement": {"CountryCodes" : []}}
        for state in range(len(old_statements["GeoMatchConstraints"])):
            temp["GeoMatchStatement"]["CountryCodes"].append(old_statements["GeoMatchConstraints"][state]["Value"])
        if len(old_statements["GeoMatchConstraints"]) == 1:
            return temp
        elif (predicate["Negated"] == True):
            tempstatement = {statementset : {"Statement" : {}}}
            tempstatement[statementset]["Statement"] = temp
            return tempstatement
        else :
            return {}
        

#builds and returns a rule
def rule_match(old_rule):
    o_rules = json.loads(sp.getoutput("aws waf-regional get-rule --rule-id " + old_rule["RuleId"]))
    o_rule = o_rules["Rule"]
    print("rebuilding rule :" + o_rule['Name'])
    rule = {
            "Name" : removespace(o_rule['Name'])+"New",
            "Priority" : old_rule["Priority"],
            "Action" : {
                old_rule['Action']["Type"][0]+old_rule['Action']["Type"][1:].lower() : {}
            },
            "Statement": {
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": removespace(o_rule['Name'])+"NewMetric"
            }
        }
    if(len(o_rule["Predicates"]) > 1):
        rule["Statement"] = {"AndStatement" : {"Statements" : []}}

    for predicate in o_rule["Predicates"]:
        if(len(o_rule["Predicates"])>1):
            rule['Statement']["AndStatement"]["Statements"].append(build_statement(predicate = predicate, num = len(o_rule["Predicates"])))
        else:
            rule['Statement'] = build_statement(predicate = predicate, num = len(o_rule["Predicates"]))
    return (rule)
