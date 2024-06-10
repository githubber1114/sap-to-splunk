from splunk_http_event_collector import http_event_collector
from hdbcli import dbapi
import boto3, json, time, sys, os, warnings, logging, hashlib, random
from datetime import datetime

warnings.filterwarnings('ignore')
testing = 0

def generate_uniqid():
    # Generate a random number
    random_num = str(random.randint(0, 99999999)).encode()

    # Generate a SHA-256 hash of the random number.
    hash_obj = hashlib.sha256(random_num)
    hex_digit = hash_obj.hexdigest()

    return hex_digit[:10]

def log_to_splunk(testevent, metrics, hdbserver, log_time, SID, log):
    payload = {}
    payload.update({"index" : "indx"})
    payload.update({"sourcetype" : "hana_avail_checks"})
    payload.update({"source" : SID.upper()})
    payload.update({"host" : hdbserver})
    payload.update({"time": log_time})
    payload.update({"event": metrics})
    log.debug(f"payload is {payload}")
    testevent.batchEvent(payload)

def lambda_handler(event, context):

    uniqid = generate_uniqid()

    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S %z')
    log = logging.getLogger(f'HNAV {uniqid}')
    log.setLevel(logging.DEBUG)

    log.info(f"Starting HANA Availability script")

    rptuid = datetime.now().strftime('%f')
    startTime = datetime.utcnow().timestamp()
    start_time=time.time()
    # global conn
    SID = event['SID'].lower()
    metrics = {}

    log.debug(f" {rptuid} Retrieving credentials from AWS Secrets Manager for {SID.upper()}")
    client = boto3.client('secretsmanager')
    TokenResponse = client.get_secret_value(
        SecretId=f'/{SID}/hana/splunkmetrics'
    )
    JsonSecret = json.loads(TokenResponse['SecretString'])
    splunk_server = JsonSecret['splunk_server']
    splunk_token = JsonSecret['splunk_token']
    mmode = int(JsonSecret['hold'])

    if mmode > 0:
        log.debug(f" Maintenance Mode activated for {SID.upper()}; Quitting")
        return

    # Create event collector object, default SSL and HTTP Event Collector Port
    testevent = http_event_collector(splunk_token, splunk_server)
    # perform a HEC reachable check
    hec_reachable = testevent.check_connectivity()
    if not hec_reachable:
        log.debug(f" {rptuid} HEC server {splunk_server} not reachable")
        sys.exit(1)
    # Set to pop null fields.  Always a good idea
    testevent.popNullFields = True

    # Log start of execution
    status = {'EVENT_TYPE': 'HANA_AVAIL_CHECKS', 'EVENT': 'START', 'UID': uniqid}
    log_to_splunk(testevent, status, JsonSecret['hdbserver'], start_time, SID, log)

    # Begin DB Connection
    try:
        conn = dbapi.connect(
            address = JsonSecret['hdbserver'],
            port = JsonSecret['hdbport'],
            user = JsonSecret['hdbuser'],
            password = JsonSecret['hdbpass'],
            encrypt='true'
        )
        cursor = conn.cursor()
    except dbapi.Error as connErr:
        log.debug(f" {rptuid} HANA connection was unsuccessful: {connErr}")
        status = {'EVENT_TYPE': 'HANA_AVAIL_CHECKS', 'EVENT': 'ERROR', 'QUERY' : 'CONNECT', 'UID': uniqid, 'DETAIL': err}
        log_to_splunk(testevent, status, JsonSecret['hdbserver'], time.time(), SID, log)
        testevent.flushBatch()
        return

        metrics['STATUS'] = 'FAIL'
        metrics['ERROR'] = connErr
        metrics['RUNTIME'] = '0.0'

    getdata = f'''
            Select "GJAHR", "AUGDT",
            sum("DMBTR") AS "DMBTR",
            sum("WRBTR") AS "WRBTR",
            sum("MWSTS") AS "MWSTS",
            sum("SKFBT") AS "SKFBT",
            sum("SKNTO") AS "SKNTO",
            sum("WSKTO") AS "WSKTO",
            sum("WMWST") AS "WMWST" ,
            sum("DMBTR_CONV") AS "DMBTR_CONV",
            sum("WRBTR_CONV") AS "WRBTR_CONV",
            sum("MWSTS_CONV") AS "MWSTS_CONV",
            sum("WMWST_CONV") AS "WMWST_CONV",
            sum("SKFBT_CONV") AS "SKFBT_CONV",
            sum("SKNTO_CONV") AS "SKNTO_CONV",
            sum("WSKTO_CONV") AS "WSKTO_CONV",
            sum("VENDOR_COUNT") AS "VENDOR_COUNT",
            sum("PUR_DOC_NUM_COUNT") AS "PUR_DOC_NUM_COUNT",
            sum("ACCT_DOC_NUM_COUNT") AS "ACCT_DOC_NUM_COUNT",
            sum("GL_ACCT_COUNT") AS "GL_ACCT_COUNT",
            sum("DMBE2") AS "DMBE2" 
            from "_SYS_BIC"."app.stp.ptp.rep/CV_PTP_REP_INVOICE_PAID" -- change to PAID
                ('PLACEHOLDER' = ('$$IP_COBA_HIER$$','N/A'),
                'PLACEHOLDER' = ('$$IP_TARGET_CURR$$','USD'),
                'PLACEHOLDER' = ('$$IP_RATE_DATE$$','1900-01-01'),
                'PLACEHOLDER' = ('$$IP_EX_TYPE$$','P'),
                'PLACEHOLDER' = ('$$IP_SPRAS$$','E')) 
            where "AUGDT" between Add_days (Current_date , -90) and Current_date
            group by "GJAHR", "AUGDT"
            order by  "GJAHR", "AUGDT";
            '''
    try:
        conn
        try:
            log.debug(f" {rptuid} Executing scripted query against {SID.upper()}")  
            dts = datetime.utcnow().timestamp()
            log.debug(f" {rptuid} Query Start Time is {dts}, aka {datetime.fromtimestamp(dts)}")  
            cursor.execute(getdata)
            qryRunTime = round(datetime.utcnow().timestamp() - dts,2)
            log.debug(f" {rptuid} Cursor executed against {SID.upper()} in {qryRunTime} seconds")  
            result = cursor.fetchall()
            log.debug(f" {rptuid} Results fetched from {SID.upper()} in {round(datetime.utcnow().timestamp() - dts,2)} seconds")  
            statcnt = len(result)
            metrics['STATUS'] = 'SUCCESS'
            metrics['ERROR'] = 'NONE'
            metrics['RECORDCNT'] = statcnt
            metrics['RUNTIME'] = qryRunTime
        except dbapi.Error as err:
            log.debug(f" {rptuid} FAIL: HANA query was unsuccessful: {err}")
            metrics['STATUS'] = 'FAIL'
            metrics['ERROR'] = err
            metrics['RECORDCNT'] = '0'
            metrics['RUNTIME'] = '0'

        log.debug(f" {rptuid} Query results: {statcnt} records returned in {qryRunTime} seconds")  
        cursor.close()
        conn.close()
    except NameError:
        log.debug(f" {rptuid} conn was not successful\n\n")
        metrics['STATUS'] = 'FAIL'

    metrics['HOST'] = JsonSecret['hdbserver']
    metrics['SID'] = SID.upper()
    metrics['USER_NAME'] = JsonSecret['hdbuser']
    metrics['STATEMENT_STRING'] = getdata
    metrics['EVENT_TYPE'] = "HANA_AVAIL_CHECKS"
    log_to_splunk(testevent, metrics, JsonSecret['hdbserver'], time.time(), SID, log)

    # Log end of execution
    status = {'EVENT_TYPE': 'HANA_AVAIL_CHECKS', 'EVENT': 'END', 'UID': uniqid}
    log_to_splunk(testevent, status, JsonSecret['hdbserver'], time.time(), SID, log)
    testevent.flushBatch()
    log.debug(f" {rptuid} Inserted status of HANA Availability Check for {SID.upper()} into Splunk: {metrics['STATUS']}")
    log.debug(f" {rptuid} HANA Availability Check script completed in {round(datetime.utcnow().timestamp() - startTime,2)} seconds\n\n")

if __name__ == '__main__':
    SID = os.environ['SID']
    lambda_handler({"SID":SID},"dummy")