import os
import json
import subprocess as sp

def create_regex_patterset(RegexPatternSetId):
    pattern_set = json.loads(sp.getoutput("aws waf get-regex-pattern-set --regex-pattern-set-id "+ RegexPatternSetId))
    pattern_set = pattern_set['RegexPatternSet']
    pattern_list = []
    for regex in pattern_set['RegexPatternStrings']:
        pattern_list.append({"RegexString" : regex})
    print(pattern_list)
    create = sp.getoutput("aws wafv2 create-regex-pattern-set --name " + pattern_set["Name"] + "set --scope REGIONAL --region ap-south-1 --regular-expression-list ' " +json.dumps(pattern_list)+"'")
    arn = json.loads(create)
    arn = arn["Summary"]["ARN"]
    return arn

def create_ipset(ipsetid):
    ip_set = json.loads(sp.getoutput("aws waf get-ip-set --ip-set-id "+ ipsetid))
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
    elif(ipv6set != ""):
        create = json.loads(sp.getoutput("aws wafv2 create-ip-set --name "+ ip_set['Name'] +"ipv6set --scope REGIONAL --ip-address-version IPV6 --addresses %s" %(ipv6set)))
        create = create["Summary"]
        arn.append(create["ARN"])
    return arn

def xss_sql_statements(old_state, i):
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



def build_statement(predicate,rule):
    statement =list()
    statementset = "OrStatement"
    if(predicate["Negated"] == True):
        statementset = "NotStatement"

    if (predicate["Type"] == "XssMatch"):
        old_statements = json.loads(sp.getoutput("aws waf get-xss-match-set --xss-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['XssMatchSet']
        temp = {statementset : {"Statements" : []}}
        for state in range(len(old_statements["XssMatchTuples"])):
            statement.append({"XssMatchStatement" : xss_sql_statements(old_state = old_statements["XssMatchTuples"][state],i = state)})
        temp[statementset]["Statements"] = statement
        rule["AndStatement"]["Statements"].append(temp)
        return rule

    elif (predicate["Type"] == "SqlInjectionMatch"):
        old_statements = json.loads(sp.getoutput("aws waf get-sql-injection-match-set --sql-injection-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['SqlInjectionMatchSet']
        temp = {statementset : {"Statements" : []}}
        for state in range(len(old_statements["SqlInjectionMatchTuples"])):
            statement.append({"SqliMatchStatement" : xss_sql_statements(old_state = old_statements["SqlInjectionMatchTuples"][state],i = state)})
        temp[statementset]["Statements"] = statement
        rule["AndStatement"]["Statements"].append(temp)
        return rule 

    elif (predicate["Type"] == "ByteMatch"):
        old_statements = json.loads(sp.getoutput("aws waf get-byte-match-set --byte-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['ByteMatchSet']
        temp = {statementset : {"Statements" : []}}
        for state in range(len(old_statements["ByteMatchTuples"])):
            bytetuple = xss_sql_statements(old_state = old_statements["ByteMatchTuples"][state],i = state)
            bytetuple['SearchString'] = old_statements["ByteMatchTuples"][state]['TargetString']
            bytetuple['PositionalConstraint'] = old_statements["ByteMatchTuples"][state]['PositionalConstraint']
            statement.append({"ByteMatchStatement" :  bytetuple})
        temp[statementset]["Statements"] = statement
        rule["AndStatement"]["Statements"].append(temp)
        return rule 

    elif (predicate["Type"] == "SizeConstraint"):
        old_statements = json.loads(sp.getoutput("aws waf get-size-constraint-set --size-constraint-set-id " + predicate["DataId"]))
        old_statements = old_statements['SizeConstraintSet']
        temp = {statementset : {"Statements" : []}}
        for state in range(len(old_statements["SizeConstraints"])):
            bytetuple = xss_sql_statements(old_state = old_statements["SizeConstraints"][state],i = state)
            bytetuple['ComparisonOperator'] = old_statements["SizeConstraints"][state]['ComparisonOperator']
            bytetuple['Size'] = old_statements["SizeConstraints"][state]['Size']
            statement.append({"SizeConstraintStatement" :  bytetuple})
        temp[statementset]["Statements"] = statement
        rule["AndStatement"]["Statements"].append(temp)
        print(rule)
        return rule 
    
    elif (predicate["Type"] == "RegexMatch"):
        old_statements = json.loads(sp.getoutput("aws waf get-regex-match-set --regex-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['RegexMatchSet']
        temp = {statementset : {"Statements" : []}}
        for state in range(len(old_statements["RegexMatchTuples"])):
            bytetuple = xss_sql_statements(old_state = old_statements["RegexMatchTuples"][state],i = state)
            bytetuple['ARN'] = create_regex_patterset(old_statements["RegexMatchTuples"][state]['RegexPatternSetId'])
            statement.append({"RegexPatternSetReferenceStatement" :  bytetuple})
        temp[statementset]["Statements"] = statement
        rule["AndStatement"]["Statements"].append(temp)
        return rule 
    
    elif (predicate["Type"] == "IPMatch"):
        ARN = create_ipset(predicate["DataId"])
    
        temp = {statementset : {"Statements" : []}}
        for ipset in ARN:
            temp[statementset]["Statements"].append({"IPSetReferenceStatement" : {"ARN": ipset}})
        rule["AndStatement"]["Statements"].append(temp)
        return rule 
    
    elif (predicate["Type"] == "GeoMatch"):
        old_statements = json.loads(sp.getoutput("aws waf get-geo-match-set --geo-match-set-id " + predicate["DataId"]))
        old_statements = old_statements['GeoMatchSet']
        tempstatement = {statementset : {"Statements" : []}}
        temp = {"GeoMatchStatement": {"CountryCodes" : []}}
        for state in range(len(old_statements["GeoMatchConstraints"])):
            temp["GeoMatchStatement"]["CountryCodes"].append(old_statements["GeoMatchConstraints"][state]["Value"])
        tempstatement[statementset]["Statements"].append(temp)
        rule["AndStatement"]["Statements"].append(tempstatement)
        print(rule)
        return rule    
    return rule


def rule_match(old_rule):
    o_rules = json.loads(sp.getoutput("aws waf get-rule --rule-id " + old_rule["RuleId"]))
    o_rule = o_rules["Rule"]
    rule = {
        "Name" : o_rule['Name']+"New",
        "Priority" : old_rule["Priority"],
        "Action" : {
            old_rule['Action']["Type"][0]+old_rule['Action']["Type"][1:].lower() : {}
        },
        "Statement": {
            "AndStatement" : {"Statements" : []}
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": o_rule['Name']+"NewMetric"
        }
    }

    for predicate in o_rule["Predicates"]:
        print(predicate)
        rule['Statement'] = build_statement(predicate = predicate,rule =rule['Statement'])
    return (rule)



    # "RateBasedStatement": {
    #     "Limit": long,
    #     "AggregateKeyType": "IP",
    #     "ScopeDownStatement": {
    #       "ByteMatchStatement": {
    #         "SearchString": blob,
    #         "FieldToMatch": {
    #           "SingleHeader": {
    #             "Name": "string"
    #           },
    #           "SingleQueryArgument": {
    #             "Name": "string"
    #           },
    #           "AllQueryArguments": {

    #           },
    #           "UriPath": {

    #           },
    #           "QueryString": {

    #           },
    #           "Body": {

    #           },
    #           "Method": {

    #           }
    #         },
    #         "TextTransformations": [
    #           {
    #             "Priority": integer,
    #             "Type": "NONE"|"COMPRESS_WHITE_SPACE"|"HTML_ENTITY_DECODE"|"LOWERCASE"|"CMD_LINE"|"URL_DECODE"
    #           }
    #           ...
    #         ],
    #         "PositionalConstraint": "EXACTLY"|"STARTS_WITH"|"ENDS_WITH"|"CONTAINS"|"CONTAINS_WORD"
    #       }