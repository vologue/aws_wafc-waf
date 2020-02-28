import subprocess as sp
import json
import rulematch

def rulebuilder(classic_rule):
    o_rule = json.loads(sp.getoutput("aws waf-regional get-rate-based-rule --rule-id " + classic_rule['RuleId']))
    o_rule = o_rule["Rule"]
    
    rule = {
        "Name" : rulematch.removespace(o_rule['Name'])+"New",
        "Priority" : classic_rule["Priority"],
        "Action" : {
            classic_rule['Action']["Type"][0]+classic_rule['Action']["Type"][1:].lower() : {}
        },
        "Statement": {
            "RateBasedStatement" : {
                "Limit": o_rule['RateLimit'],
                "AggregateKeyType": o_rule['RateKey'],
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": o_rule['Name']+"NewMetric"
        }
    }

    if(len(o_rule["MatchPredicates"])>1):
        rule["Statement"]["RateBasedStatement"]["ScopeDownStatement"] = {"AndStatement" : {"Statements" : []}} 
    
    for predicate in o_rule["MatchPredicates"]:
       
        if(len(o_rule["MatchPredicates"])>1):
            rule['Statement']['RateBasedStatement']["ScopeDownStatement"]["AndStatement"]["Statements"].append(rulematch.build_statement(predicate = predicate,num = len(o_rule["MatchPredicates"])))
        else:
            rule['Statement']['RateBasedStatement']["ScopeDownStatement"] = rulematch.build_statement(predicate = predicate,num = len(o_rule["MatchPredicates"]))
    
    return rule