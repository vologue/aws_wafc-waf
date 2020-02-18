import os
import json
def match(p_type, id):
    if(p_type == "GeoMatch"):
        country_codes = []
        geomatchset = json.loads(os.popen('aws waf get-geo-match-set --geo-match-set-id %s' %(id)).read())['GeoMatchSet'] 
        for country in geomatchset['GeoMatchConstraints']:
            country_codes.append(country['Value'])
        ret_dict={
            "GeoMatchStatement" : {
                "CountryCodes": country_codes
            }
        }
        print(json.dumps(ret_dict))
        return(json.dumps(ret_dict))
    elif (p_type == "XssMatch"):
        xssmatchset = json.loads(os.popen('aws waf get-xss-match-set --xss-match-set-id %s' %(id)).read())['XssMatchSet'] 
        


        # "XssMatchStatement": {
        # "FieldToMatch": {
        #   "SingleHeader": {
        #     "Name": "string"
        #   },
        #   "SingleQueryArgument": {
        #     "Name": "string"
        #   },
        #   "AllQueryArguments": {

        #   },
        #   "UriPath": {

        #   },
        #   "QueryString": {

        #   },
        #   "Body": {

        #   },
        #   "Method": {

        #   }
        # },

match(p_type="GeoMatch", id="f49638c3-cae2-4882-b2bf-2cfe0ef8a24d")