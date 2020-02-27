aws wafv2 create-rule-group --name $1 \
--scope REGIONAL \
--capacity 1500 \
--rules 'file://rulegroup.json' \
--visibility-config $2 \
--region ap-south-1 