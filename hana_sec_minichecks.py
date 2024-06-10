from splunk_http_event_collector import http_event_collector
from hdbcli import dbapi
import boto3, time, sys, os, warnings, logging, hashlib, random
from datetime import datetime

warnings.filterwarnings('ignore')

def generate_uniqid():
    # Generate a random number
    random_num = str(random.randint(0, 99999999)).encode()

    # Generate a SHA-256 hash of the random number.
    hash_obj = hashlib.sha256(random_num)
    hex_digit = hash_obj.hexdigest()

    return hex_digit[:10]

def log_to_splunk(testevent, metrics, hdbserver, SID, log, start_time=time.time()):
    payload = {}
    payload.update({"index" : "twdc_sap_hana"})
    payload.update({"sourcetype" : "hana_sec_minichecks"})
    payload.update({"source" : SID.upper()})
    payload.update({"host" : hdbserver})
    payload.update({"time": start_time})
    payload.update({"event": metrics})
    log.debug(f"payload is {payload}")
    testevent.batchEvent(payload)

def lambda_handler(event, context):

    uniqid = generate_uniqid()

    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S %z')
    log = logging.getLogger(f'HSMC {uniqid}')
    log.setLevel(logging.DEBUG)

    start_time = time.time()
    SID = event['SID'].lower()
    log.debug(f"Starting HANA Security Minichecks script")
    log.debug(f"Retrieving credentials from AWS Secrets Manager for {SID.upper()}")
    client = boto3.client('secretsmanager')
    TokenResponse = client.get_secret_value(
        SecretId=f'/{SID}/hana/splunkmetrics'
    )
    secret = eval(TokenResponse['SecretString'])
    splunk_server = secret['splunk_server']             # Splunk server FQDN
    splunk_token = secret['splunk_token']               # HEC Token
    mmode = int(secret['hold'])                         # Maintenance Mode Flag

    # Use Splunk QA (for testing purposes)
    # splunk_server = 'hec-idx-us-east-1.qa.splunk.disney.com'                            # testing
    # splunk_token = '52FF2510-F4FE-4B78-83AA-A244B8575134'

    # Create event collector object, default SSL and HTTP Event Collector Port
    testevent = http_event_collector(splunk_token, splunk_server)

    # Log end of execution
    status = {'EVENT_TYPE': 'HANA_SEC_MINICHECK', 'EVENT': 'START', 'UID': uniqid}
    log_to_splunk(testevent, status, secret['hdbserver'], SID, log)

    if mmode > 0:
        log.debug(f"Maintenance Mode activated for {SID.upper()}; Quitting")
        return
    
    # Begin DB Connection
    try:
        conn = dbapi.connect(
            address = secret['hdbserver'],
            port = secret['hdbport'],
            user = secret['hdbuser'],
            password = secret['hdbpass'],
            encrypt='true'
        )
    except dbapi.Error as err:
        log.critical(f"Failed to connect to {SID.upper()}; {err} Quitting")
        status = {'EVENT_TYPE': 'HANA_SEC_MINICHECK', 'EVENT': 'ERROR', 'QUERY' : 'CONNECT', 'UID': uniqid, 'DETAIL': err}
        log_to_splunk(testevent, status, secret['hdbserver'], SID, log)
        testevent.flushBatch()
        return
    
    cursor = conn.cursor()

    # Open and read the file as a single buffer
    # following line with encoding is only needed to strip some Windows special characters, if present
    # fd = open('bseg_insert.sql', 'r', encoding='utf-8-sig')
    fd = open('HANA_Security_MiniChecks_2.00.030+.txt', 'r', encoding='utf-8-sig')
    sqlFile = fd.read()
    fd.close()

    # perform a HEC reachable check
    hec_reachable = testevent.check_connectivity()
    if not hec_reachable:
        log.debug(f"HEC server {splunk_server} not reachable")
        sys.exit(1)

    # Set to pop null fields.  Always a good idea
    testevent.popNullFields = True

    # payload = {}
    # payload.update({"index" : "twdc_sap_hana"})
    # payload.update({"sourcetype" : "hana_sec_minichecks"})
    # payload.update({"source" : SID.upper()})
    # payload.update({"host" : secret['hdbserver']})

    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log.debug(f"Executing query to {SID}")
    prevchid = ""
    prevdesc = ""   

    try:
        cursor.execute(sqlFile)
        result = cursor.fetchall()
        cursor.close()
        conn.close()
    except dbapi.Error as err:
        log.critical(f"HANA query to run security minicheck was unsuccessful: {err}")
        status = {'EVENT_TYPE': 'HANA_SEC_MINICHECK', 'EVENT': 'ERROR', 'UID': uniqid, 'QUERY' : sqlFile, 'DETAIL': err}
        log_to_splunk(testevent, status, secret['hdbserver'], SID, log)
    i=0
    for row in result:
        metrics = {}
        metrics['CHID']=row[0]
        metrics['DESCRIPTION']=row[1]
        metrics['VALUE']=row[2]
        metrics['EXPECTED_VALUE']=row[3]
        metrics['C']=row[4]
        if metrics['C'] == "":
            metrics['C'] = " "
        metrics['SAP_NOTE']=row[5]
        metrics['SID'] = SID.upper()
        metrics['EVENT_TYPE'] = "HANA_SEC_MINICHECK"
        metrics['TIMESTAMP'] = timestamp
        metrics['ORDER'] = i
        if "S" in metrics['CHID']:
            prevchid = metrics['CHID']
            prevdesc = metrics['DESCRIPTION']
        elif metrics['CHID'] == "":
            if metrics['VALUE'] == "":
                next
            elif "S" in prevchid:
                metrics['CHID'] = prevchid
                metrics['DESCRIPTION'] = prevdesc
        metrics['UID'] = uniqid
        log_to_splunk(testevent, metrics, secret['hdbserver'], SID, log, start_time)
        i=i+1
        
    # Log end of execution
    status = {'EVENT_TYPE': 'HANA_SEC_MINICHECK', 'EVENT': 'END', 'UID': uniqid}
    log_to_splunk(testevent, status, secret['hdbserver'], SID, log)
    # Flush the batch 
    log.debug(f"flushing the batch")
    testevent.flushBatch()
    log.debug(f"Inserted {i} records for {SID.upper()} into Splunk")
    log.debug(f"Script completed in {round(time.time() - start_time,2)} seconds")

if __name__ == '__main__':
    SID = os.environ['SID']
    lambda_handler({"SID":SID},"dummy")
