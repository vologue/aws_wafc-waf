aws wafv2 create-web-acl --name $1 \
--scope REGIONAL \
--default-action Block={} \
--rules 'file://rulegroup.json' \
--visibility-config $2 \
--region ap-south-1  

# --capacity 1500 