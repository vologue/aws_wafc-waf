import os
import json
import subprocess as sp
from statement_builder import *
import createset


#Handling whitespaces and '&' in the names
def removespace(name):
    temp =  ''.join(name.split(" "))
    return 'And'.join(temp.split("&"))

# builds the statement 
def build_statement(predicate):
    statement =list()
    statementset = "OrStatement"
    if(predicate["Negated"] == True):
        statementset = "NotStatement"

    if (predicate["Type"] == "XssMatch"):
        return build_xss_statement(predicate = predicate, statement=statement, statementset = statementset)
    
    elif (predicate["Type"] == "SqlInjectionMatch"):
        return build_sql_statement(predicate = predicate, statement=statement, statementset = statementset)

    elif (predicate["Type"] == "ByteMatch"):
        return build_bytematch_statement(predicate = predicate, statement=statement, statementset = statementset)

    elif (predicate["Type"] == "SizeConstraint"):
        return build_sizematch_statement(predicate = predicate, statement=statement, statementset = statementset)

    elif (predicate["Type"] == "RegexMatch"):
        return build_regexmatch_statement(predicate = predicate, statement=statement, statementset = statementset)

    elif (predicate["Type"] == "IPMatch"):
        return build_ipmatch_statement(predicate = predicate, statement=statement, statementset = statementset)
    
    elif (predicate["Type"] == "GeoMatch"):
        return build_geomatch_statement(predicate = predicate, statement=statement, statementset = statementset)
    
        

#builds and returns a rule
def rule_match(old_rule):
    o_rules = json.loads(sp.getoutput("aws waf-regional get-rule --rule-id " + old_rule["RuleId"]))
    o_rule = o_rules["Rule"]
    print("rebuilding rule :" + o_rule['Name'])
    print("Region : " + createset.region)
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
            rule['Statement']["AndStatement"]["Statements"].append(build_statement(predicate = predicate))
        else:
            rule['Statement'] = build_statement(predicate = predicate)
    return (rule)
