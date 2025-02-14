from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import urllib.request, urllib.parse, urllib.error
import httplib2
from xml.dom import minidom

baseurl = 'https://192.168.2.10:8089'
userName = 'admin'
password = 'password'
correlation_search_name = 'Threat - blfz_test - Rule'
new_search_query = '| inputlookup updated_ioc_domains.csv | head 10'
new_description = 'Salam Aleykum'

# Authenticate with server.
http = httplib2.Http(disable_ssl_certificate_validation=True)
serverContent = http.request(
    baseurl + '/services/auth/login',
    'POST', headers={}, 
    body=urllib.parse.urlencode({'username': userName, 'password': password})
)[1]

sessionKey = minidom.parseString(serverContent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue

# Correct Correlation Search API Path
encoded_search_name = urllib.parse.quote(correlation_search_name)
update_url = f"{baseurl}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{encoded_search_name}"

# Include additional parameters for correlation search
update_body = urllib.parse.urlencode({
    'search': new_search_query, 
    'description': new_description,
    'action.correlationsearch.enabled': '1',  # Ensure it remains a correlation search
    #'action.correlationsearch.label': 'Threat Detection'  # Optional: Set a label
})

response, content = http.request(update_url, 'POST',
    headers={'Authorization': f'Splunk {sessionKey}', 'Content-Type': 'application/x-www-form-urlencoded'},
    body=update_body
)

# Error Control
if response.status == 200:
    print("Correlation search successfully updated!")
else:
    print(f"Error updating correlation search! HTTP Status: {response.status}")
    print(content.decode('utf-8'))