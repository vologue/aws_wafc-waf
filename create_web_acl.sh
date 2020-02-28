aws wafv2 create-web-acl --name $1 \
--scope REGIONAL \
--rules file://rulegroup.json \
--default-action Block={} \
--visibility-config $2 \
--region ap-south-1  

# --capacity 1500 