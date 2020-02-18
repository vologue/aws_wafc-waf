import os 
import json 
val  = json.loads(os.popen('aws waf list-web-acls').read())
for acl in val['WebACLs']:
    acl_id = acl['WebACLId']
    acl_desc = json.loads(os.popen('aws waf get-web-acl --web-acl-id %s' %(acl_id)).read())['WebACL']
    def_action = acl_desc['DefaultAction']
    name = acl_desc['Name']
    visibilityconfig = "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=TestWebAclMetrics"
    region = "ap-south-1"
    scope = "REGIONAL"
    
    print(acl_des)
    #'get-rule --rule-id'
    # aws wafv2 create-web-acl \
    # --name TestWebAcl \
    # --scope REGIONAL \
    # --default-action Allow={} \
    # --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=TestWebAclMetrics \
    # --rules file://waf-rule.json \
    # --region us-west-2
    # contents of waf-rule.json
#     [
#     {
#         "Name":"basic-rule",
#         "Priority":0,
#         "Statement":{
#             "AndStatement":{
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