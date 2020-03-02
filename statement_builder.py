import subprocess as sp
import json
from createset import *

#builds geomatch statements
def build_geomatch_statement(predicate, statement,statementset):
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

# builds ipmatch statements
def build_ipmatch_statement(predicate, statement,statementset):
    ARN = create_ipset(predicate["DataId"])

    if (len(ARN) == 1 and predicate["Negated"] == True):
        temp = {statementset : {"Statement" : {}}}
        for ipset in ARN:
            temp[statementset]["Statement"] = {"IPSetReferenceStatement" : {"ARN": ipset}}
        return temp
    elif len(ARN)==1:
        return {"IPSetReferenceStatement" : {"ARN": ARN[0]}}
    elif (len(ARN) >1 and predicate["Negated"] == True):
        temp = {statementset : {"Statement" : {"AndStatement" : {"Statements" : []}}}}
        for ipset in ARN:
            temp[statementset]["Statement"]["AndStatement"]["Statements"].append({"IPSetReferenceStatement" : {"ARN": ipset}})
        return temp
    elif (len(ARN) >1):
        temp = {statementset : {"Statements" : []}}
        for ipset in ARN:
            temp[statementset]["Statements"].append({"IPSetReferenceStatement" : {"ARN": ipset}})

        return temp
    else:
        return {}


#builds regexmatch statements
def build_regexmatch_statement(predicate, statement,statementset):
    old_statements = json.loads(sp.getoutput("aws waf-regional get-regex-match-set --regex-match-set-id " + predicate["DataId"]))
    old_statements = old_statements['RegexMatchSet']
    for state in range(len(old_statements["RegexMatchTuples"])):
        bytetuple = match_fields(old_state = old_statements["RegexMatchTuples"][state],i = state)
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

#builds sizematch statements
def build_sizematch_statement(predicate, statement,statementset):
    old_statements = json.loads(sp.getoutput("aws waf-regional get-size-constraint-set --size-constraint-set-id " + predicate["DataId"]))
    old_statements = old_statements['SizeConstraintSet']
    for state in range(len(old_statements["SizeConstraints"])):
        bytetuple = match_fields(old_state = old_statements["SizeConstraints"][state],i = state)
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


# Builds bytematch statements
def build_bytematch_statement(predicate, statement,statementset):
    old_statements = json.loads(sp.getoutput("aws waf-regional get-byte-match-set --byte-match-set-id " + predicate["DataId"]))
    old_statements = old_statements['ByteMatchSet']
    for state in range(len(old_statements["ByteMatchTuples"])):
        bytetuple = match_fields(old_state = old_statements["ByteMatchTuples"][state],i = state)
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

#builds sql statements
def build_sql_statement(predicate, statement,statementset):
    old_statements = json.loads(sp.getoutput("aws waf-regional get-sql-injection-match-set --sql-injection-match-set-id " + predicate["DataId"]))
    old_statements = old_statements['SqlInjectionMatchSet']
    for state in range(len(old_statements["SqlInjectionMatchTuples"])):
        statement.append({"SqliMatchStatement" : match_fields(old_state = old_statements["SqlInjectionMatchTuples"][state],i = state)})
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

# Builds Xss statements
def build_xss_statement(predicate, statement,statementset):
    old_statements = json.loads(sp.getoutput("aws waf-regional get-xss-match-set --xss-match-set-id " + predicate["DataId"]))
    old_statements = old_statements['XssMatchSet']
    for state in range(len(old_statements["XssMatchTuples"])):
        statement.append({"XssMatchStatement" : match_fields(old_state = old_statements["XssMatchTuples"][state],i = state)})
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

# defines fields and text transformations
def match_fields(old_state, i):
    statement = { "FieldToMatch": {},
            "TextTransformations": []
        }

    if old_state["FieldToMatch"]["Type"] == "HEADER":
        statement["FieldToMatch"]["SingleHeader"] = {
            "Name" : old_state["FieldToMatch"]["Data"]
        }
        
    elif old_state["FieldToMatch"]["Type"] == "SINGLE_QUERY_ARG":
        statement["FieldToMatch"]["SingleQueryArgument"] = {
            "Name" : old_state["FieldToMatch"]["Data"]
        }
    elif old_state["FieldToMatch"]["Type"] == "ALL_QUERY_ARGS":
        statement["FieldToMatch"]["AllQueryArguments"] = {}
    
    elif old_state["FieldToMatch"]["Type"] == "URI":
        statement["FieldToMatch"]["UriPath"] = {}

    elif old_state["FieldToMatch"]["Type"] == "QUERY_STRING":
        statement["FieldToMatch"]["QueryString"] = {}

    elif old_state["FieldToMatch"]["Type"] == "BODY":
        statement["FieldToMatch"]["Body"] = {}

    elif old_state["FieldToMatch"]["Type"] == "METHOD":
        statement["FieldToMatch"]["Method"] = {}

    statement["TextTransformations"].append({
            "Priority": i, "Type" : old_state["TextTransformation"]
        })
    return statement