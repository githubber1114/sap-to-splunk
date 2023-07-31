from splunk_http_event_collector import http_event_collector
from hdbcli import dbapi
import boto3, json, time, sys, os, warnings
from datetime import datetime
# import pandas as pd

warnings.filterwarnings('ignore')

def lambda_handler(event, context):

    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Starting HANA Configuration Minichecks script")
    start_time = time.time()
    SID = event['SID'].lower()
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Retrieving credentials from AWS Secrets Manager")
    client = boto3.client('secretsmanager')
    TokenResponse = client.get_secret_value(
        SecretId=f'/{SID}/hana/splunkmetrics'
    )
    JsonSecret = json.loads(TokenResponse['SecretString'])
    splunk_server = JsonSecret['splunk_server']
    splunk_token = JsonSecret['splunk_token']

    # Begin DB Connection
    conn = dbapi.connect(
        address = JsonSecret['hdbserver'],
        port = JsonSecret['hdbport'],
        user = JsonSecret['hdbuser'],
        password = JsonSecret['hdbpass'],
        encrypt='true'
    )
    cursor = conn.cursor()

    # Open and read the file as a single buffer
    # following line with encoding is only needed to strip some Windows special characters, if present
    # fd = open('bseg_insert.sql', 'r', encoding='utf-8-sig')
    fd = open('HANA_Configuration_MiniChecks_2.00.043+.txt', 'r', encoding='utf-8-sig')
    sqlFile = fd.read()
    fd.close()

    # Create event collector object, default SSL and HTTP Event Collector Port
    testevent = http_event_collector(splunk_token, splunk_server)

    # perform a HEC reachable check
    hec_reachable = testevent.check_connectivity()
    if not hec_reachable:
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} HEC server {splunk_server} not reachable")
        sys.exit(1)

    # Set to pop null fields.  Always a good idea
    testevent.popNullFields = True

    payload = {}
    payload.update({"index" : "twdc_sap_hana"})
    payload.update({"sourcetype" : "hana_minichecks"})
    payload.update({"source" : SID.upper()})
    payload.update({"host" : JsonSecret['hdbserver']})

    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Executing query to {SID}")
    prevchid = ""
    prevdesc = ""   

    try:
        cursor.execute(sqlFile)
        result = cursor.fetchall()
    except dbapi.Error as err:
        print ("HANA query was unsuccessful: ", err)
    i=0
    for row in result:
        metrics = {}
        metrics['CHID']=row[0]
        metrics['DESCRIPTION']=row[1]
        metrics['HOST']=row[2]
        metrics['VALUE']=row[3]
        metrics['EXPECTED_VALUE']=row[4]
        metrics['C']=row[5]
        metrics['SAP_NOTE']=row[6]
        metrics['SID'] = SID.upper()
        metrics['EVENT_TYPE'] = "HANA_MINICHECK"
        metrics['TIMESTAMP'] = timestamp
        metrics['ORDER'] = i
        if "M" in metrics['CHID']:
            prevchid = metrics['CHID']
            prevdesc = metrics['DESCRIPTION']
        elif metrics['CHID'] == "":
            if metrics['VALUE'] == "":
                next
            elif "M" in prevchid:
                metrics['CHID'] = prevchid
                metrics['DESCRIPTION'] = prevdesc
        if metrics['C'] == "":
            metrics['C'] = " "
        payload.update({"event":metrics})
        testevent.batchEvent(payload)
        i=i+1
        
    testevent.flushBatch()
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Inserted {i} records for {SID.upper()} into Splunk")
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Script completed in {round(time.time() - start_time,2)} seconds")
    cursor.close()
    conn.close()

if __name__ == '__main__':
    SID = os.environ['SID']
    lambda_handler({"SID":SID},"dummy")