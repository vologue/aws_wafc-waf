import os 
import json 
import rulematch
val  = json.loads(os.popen('aws waf list-web-acls').read())
for acl in val['WebACLs']:
    acl_id = acl['WebACLId']
    acl_desc = json.loads(os.popen('aws waf get-web-acl --web-acl-id %s' %(acl_id)).read())['WebACL']
    def_action = acl_desc['DefaultAction']['Type']
    name = acl_desc['Name']+'NewAcl'
    visibilityconfig = "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="+name+"METRICS"
    region = "ap-south-1"
    scope = "REGIONAL"
    rules = list()
    for r in acl_desc['Rules']:
        print(r)
        rules.append(rulematch.rule_match(r))
    print()
    print()
    print(json.dumps(rules))
    #'get-rule --rule-id'
    # aws wafv2 create-web-acl \
    # --name TestWebAcl \
    # --scope REGIONAL \
    # --default-action Allow={} \
    # --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=TestWebAclMetrics \
    # --rules file://waf-rule.json \
    # --region ap-south-1
    # contents of waf-rule.json
#     [
#     {
#         "Name":"basic-rule",
#         "Priority":0,
#         "Statement":{
#             "OrStatement":{
#                 "Statements":[
#                     {
#                         "ByteMatchStatement":{
#                             "SearchString":"example.com",
#                             "FieldToMatch":{
#                                 "SingleHeader":{
#                                     "Name":"host"
#                                 }
#                             },
#                             "TextTransformations":[
#                                 {
#                                     "Priority":0,
#                                     "Type":"LOWERCASE"
#                                 }
#                             ],
#                             "PositionalConstraint":"EXACTLY"
#                         }
#                     },
#                     {
#                         "GeoMatchStatement":{
#                             "CountryCodes":[
#                                 "US",
#                                 "IN"
#                             ]
#                         }
#                     }
#                 ]
#             }
#         },
#         "Action":{
#             "Allow":{

#             }
#         },
#         "VisibilityConfig":{
#             "SampledRequestsEnabled":true,
#             "CloudWatchMetricsEnabled":true,
#             "MetricName":"basic-rule"
#         }
#     }
# ]