from splunk_http_event_collector import http_event_collector
from hdbcli import dbapi
import boto3, time, os, warnings, logging, hashlib, random
from datetime import datetime

warnings.filterwarnings('ignore')

def generate_uniqid():
    # Generate a random number
    random_num = str(random.randint(0, 99999999)).encode()

    # Generate a SHA-256 hash of the random number.
    hash_obj = hashlib.sha256(random_num)
    hex_digit = hash_obj.hexdigest()

    return hex_digit[:10]

def log_to_splunk(testevent, metrics, hdbserver, start_time, SID, log):
    payload = {}
    payload.update({"index" : "indx"})
    payload.update({"sourcetype" : "hana_minichecks"})
    payload.update({"source" : SID.upper()})
    payload.update({"host" : hdbserver})
    payload.update({"time": start_time})
    payload.update({"event": metrics})
    log.debug(f"payload is {payload}")
    testevent.batchEvent(payload)

def lambda_handler(event, context):

    uniqid = generate_uniqid()

    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S %z')
    log = logging.getLogger(f'HMC {uniqid}')
    log.setLevel(logging.DEBUG)

    log.info(f"Starting HANA Configuration Minichecks script")
    start_time = time.time()
    SID = event['SID'].lower()
    log.debug(f"Retrieving credentials from AWS Secrets Manager for {SID.upper()}")
    client = boto3.client('secretsmanager')
    TokenResponse = client.get_secret_value(
        SecretId=f'/{SID}/hana/splunkmetrics'
    )
    secret = eval(TokenResponse['SecretString'])
    splunk_server = secret['splunk_server']             # Splunk server FQDN
    splunk_token = secret['splunk_token']               # HEC Token
    mmode = int(secret['hold'])                         # Maintenance Mode Flag
    mcv = secret['mcv']                                 # Minicheck version (file name)

    if mmode > 0:
        log.info(f"Maintenance Mode activated for {SID.upper()}; Quitting")
        return

    # Open and read the file as a single buffer
    # following line with encoding is only needed to strip some Windows special characters, if present
    # fd = open('bseg_insert.sql', 'r', encoding='utf-8-sig')
    fd = open(mcv, 'r', encoding='utf-8-sig')
    sqlFile = fd.read()
    fd.close()

    # Create event collector object, default SSL and HTTP Event Collector Port
    testevent = http_event_collector(splunk_token, splunk_server)

    # perform a HEC reachable check
    hec_reachable = testevent.check_connectivity()
    if not hec_reachable:
        log.critical(f"HEC server {splunk_server} not reachable; quitting")
        return 1

    # Set to pop null fields.  Always a good idea
    testevent.popNullFields = True

    # Log start of execution
    status = {'EVENT_TYPE': 'HANA_MINICHECK', 'EVENT': 'START', 'UID': uniqid}
    log_to_splunk(testevent, status, secret['hdbserver'], start_time, SID, log)

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
        status = {'EVENT_TYPE': 'HANA_MINICHECK', 'EVENT': 'ERROR', 'QUERY' : 'CONNECT', 'DETAIL': err, 'UID': uniqid}
        log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
        testevent.flushBatch()
        return 1

    cursor = conn.cursor()

    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log.debug(f"Executing query to {SID}")
    prevchid = ""
    prevdesc = ""   

    try:
        cursor.execute(sqlFile)
        result = cursor.fetchall()
    except dbapi.Error as err:
        log.critical(f"HANA query to run minicheck was unsuccessful: {err}")
        status = {'EVENT_TYPE': 'HANA_MINICHECK', 'EVENT': 'ERROR', 'QUERY' : mcv, 'DETAIL': err, 'UID': uniqid}
        log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
        testevent.flushBatch()
        return 1
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
        metrics['UID'] = uniqid
        log_to_splunk(testevent, metrics, secret['hdbserver'], start_time, SID, log)
        i=i+1
        
    # Log end of execution
    status = {'EVENT_TYPE': 'HANA_MINICHECK', 'EVENT': 'END', 'UID': uniqid}
    log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)

    testevent.flushBatch()
    log.info(f"Inserted {i} records for {SID.upper()} into Splunk")
    log.info(f"Script completed in {round(time.time() - start_time,2)} seconds")
    cursor.close()
    conn.close()

if __name__ == '__main__':
    SID = os.environ['SID']
    lambda_handler({"SID":SID},"dummy")