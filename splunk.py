from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import urllib.request, urllib.parse, urllib.error
import httplib2
from xml.dom import minidom

baseurl = 'https://192.168.2.10:8089'
userName = 'admin'
password = 'P@ssword'
correlation_search_name = 'Threat - blfz_test - Rule' # Correlation Search
# correlation_search_name = 'blfz_Excessive Failed Login Activity' # Saved Search
new_search_query = 'index=linux | inputlookup excluldedHosts.csv | head 10'
new_description = '16.02.2025 tarixinde update olundu'
#cron_schedule ='*/1 * * * *'

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


# Update Correlation Search:
update_url = f"{baseurl}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{encoded_search_name}" 

# Saved Search Operations:
# update_url = f"{baseurl}/services/saved/searches/{encoded_search_name}" # Update Saved Search
# update_url = f"{baseurl}//servicesNS/admin/search/saved/searches/{encoded_search_name}" # Delete Saved Search



# Include additional parameters for correlation search
update_body = urllib.parse.urlencode({
    'search': new_search_query, 
    'description': new_description,
    'action.correlationsearch.enabled': '1',  # Ensure it remains a correlation search
    #'cron_schedule':cron_schedule
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



#Documentation link: https://docs.splunk.com/Documentation/Splunk/8.0.4/RESTREF/RESTsearch