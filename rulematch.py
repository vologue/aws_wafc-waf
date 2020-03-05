import os
import json
import subprocess as sp
from statement_builder import *
import createset


#Handling whitespaces and '&' in the names
def make_regex_compliant(name):
    temp =  ''.join(name.split(" "))
    return 'And'.join(temp.split("&"))


# builds the statement 
def build_statement(predicate):
    statement =list()
    statementset = "OrStatement"
    if(predicate["Negated"] == True):
        statementset = "NotStatement"
    # to decide which function to call 
    switcher = {
        "XssMatch": build_xss_statement,
        "SqlInjectionMatch": build_sql_statement,
        "ByteMatch": build_bytematch_statement,
        "SizeConstraint": build_sizematch_statement,
        "RegexMatch": build_regexmatch_statement,
        "IPMatch": build_ipmatch_statement,
        "GeoMatch": build_geomatch_statement,
    }
    function = switcher.get(predicate["Type"], lambda: "Invalid Statement")
    return function(predicate = predicate , statement = statement, statementset = statementset)
        

#builds and returns a rule
def rule_match(old_rule):
    o_rules = json.loads(sp.getoutput("aws waf-regional get-rule --rule-id " + old_rule["RuleId"]))
    o_rule = o_rules["Rule"]
    print("rebuilding rule :" + o_rule['Name'])
    print("Region : " + createset.region)
    rule = {
            "Name" : make_regex_compliant(o_rule['Name'])+"New",
            "Priority" : old_rule["Priority"],
            "Action" : {
                old_rule['Action']["Type"][0]+old_rule['Action']["Type"][1:].lower() : {}
            },
            "Statement": {
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": make_regex_compliant(o_rule['Name'])+"NewMetric"
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
