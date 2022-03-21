import requests
import json
import keyring
import urllib3
urllib3.disable_warnings()

# from a python prompt, run:
#   import keyring
#   keyring.set_password("<descriptor, eg sid>", "<username>", "<password>")
# to set password for retrieval here
solmanpass = keyring.get_password("<solman sid>", "<solman username>")

basicAuthCredentials = ('<solman username>', solmanpass)
request_headers = {
    'Accept': 'application/json'
}

def get_event_list(contextid, systemid):
    # Step 2: EventListSet - get a list of all metrics specific to this system, and their associated values
    url = 'http://<solman server:port>/sap/opu/odata/sap/AI_SYSMON_OVERVIEW_SRV/EventListSet?search={}'.format(contextid)
    response = requests.get(url
                            , auth=basicAuthCredentials
                            , headers=request_headers
                           )
    if response.status_code == 200:
        metrics = {}
        metrics['SID'] = sid
        json_dict = response.json().get('d', {})
        json_results = json_dict.get('results', {})
        for i in range(len(json_results)):
            nam = json_dict["results"][i]['EventName']
            val = json_dict["results"][i]['ValueLast']
            # Ignore metrics with a value of '0.000', unless it's CPU-related
            if ((val != '0.000') 
                                or ('CPU' in nam)
            ):
                metrics[nam] = val
            # See what we're missing
            else:
                print('Not inserted: {} : {} : {}'.format(sid, nam, val))
        if len(metrics) > 1:
            splunk_dict = {"index":"<splunk index name>", "event": metrics }
            #splunk url eg: url='https://<hec-server-name>/services/collector/event'
            url='<splunk url>'
            authHeader = {'Authorization': 'Splunk {}'.format('<splunk token>')}
            r = requests.post(url, headers=authHeader, json=splunk_dict, verify=False)
            print('Inserting into Splunk status:')
            print(r.text)
        return len(metrics)

# Step 1: SystemListSet - get a list of all systems which Solution Manager is monitoring
url = 'http://<solman server:port>/sap/opu/odata/sap/AI_SYSMON_OVERVIEW_SRV/SystemListSet'
response = requests.get(url
                        , auth=basicAuthCredentials
                        , headers=request_headers
                       )
if response.status_code == 200:
    json_dict = response.json().get('d', {})
    json_results = json_dict.get('results', {})
    for i in range(len(json_results)):
        cid = json_dict["results"][i]["Contextid"]
        sid = json_dict["results"][i]["Name"]
        if cid != "":
            # print("Found ID for {} which is {}".format(sid, cid))
            total = get_event_list(cid, sid)
            print("Inserted {} metrics for {} into Splunk\n".format(total, sid))
