from splunk_http_event_collector import http_event_collector
from hdbcli import dbapi
import boto3, time, os, warnings, logging, hashlib, random
from datetime import datetime, timezone

warnings.filterwarnings('ignore')

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
    payload.update({"sourcetype" : "hana_audit"})
    payload.update({"source" : SID.upper()})
    payload.update({"host" : hdbserver})
    payload.update({"time": log_time})
    payload.update({"event": metrics})
    log.debug(f"payload is {payload}")
    testevent.batchEvent(payload)

def lambda_handler(event, context):

    uniqid = generate_uniqid()

    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S %z')
    log = logging.getLogger(f'HNAUDIT {uniqid}')
    log.setLevel(logging.DEBUG)

    log.info(f"Starting HANA Audit Log script")

    start_time = time.time()
    SID = event['SID'].lower()
    log.info(f"Retrieving credentials from AWS Secrets Manager for {SID.upper()}")
    client = boto3.client('secretsmanager')
    TokenResponse = client.get_secret_value(
        SecretId=f'/{SID}/hana/splunkmetrics'
    )

    secret = eval(TokenResponse['SecretString'])
    splunk_server = secret['splunk_server']
    splunk_token = secret['splunk_token']
    mmode = int(secret['hold'])


    if mmode > 0:
        log.debug(f"Maintenance Mode activated for {SID.upper()}; Quitting")
        return

    # Create event collector object, default SSL and HTTP Event Collector Port
    testevent = http_event_collector(splunk_token, splunk_server)
    # perform a HEC reachable check
    hec_reachable = testevent.check_connectivity()
    if not hec_reachable:
        log.critical(f"HEC server {splunk_server} not reachable")
        return 1

    # Log start of execution
    status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'START', 'UID': uniqid}
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
        status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'ERROR', 'QUERY' : 'CONNECT', 'UID': uniqid, 'DETAIL': err}
        log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
        testevent.flushBatch()
        return

    # global cursor
    cursor = conn.cursor()

    try:
        tst = "select * from m_system_overview"
        cursor.execute(tst)
        result = cursor.fetchall()
    except dbapi.Error as err:
        log.critical(f"HANA query to test connectivity was unsuccessful: {err}")
        status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'ERROR', 'QUERY' : tst, 'DETAIL': err, 'UID': uniqid}
        log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
        testevent.flushBatch()
        return 1

    # Set to pop null fields.  Always a good idea
    testevent.popNullFields = True
    dt = datetime.now(timezone.utc) 
    utc_time = dt.replace(tzinfo=timezone.utc) 
    nowts = utc_time.timestamp() 
    prvts=1672549200
    hourdiff = nowts - prvts

    while hourdiff > 3600:
        # Retrieve the timestamp of the most recent record in the control table (last entry sent to Splunk)
        lstts, lstdt = lastts(testevent, secret['hdbserver'], SID, cursor, log, uniqid)
        # Retrieve the timestamp of the most recent record in the AUDIT_LOG table
        mxts, mxdt = maxts(testevent, secret['hdbserver'], SID, cursor, log, uniqid)
        if not lstts or not lstdt or not mxts or not mxdt:
            log.error(f"Timestamps not properly determined. Ending.") 
            return 1
        if lstts >= mxts:
            log.info(f"Last {lstdt} >= Max {mxdt}. Nothing to retrieve. Ending.") 
            status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'END', 'UID': uniqid}
            log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
            # Flush the batch 
            log.debug(f"flushing the batch")
            testevent.flushBatch()
            return
        hourdiff = mxts - lstts
        # Set hourdiff to 2 hours. Used to be 1 but then it could never get past DST in the fall.
        if hourdiff > 7200:
            log.debug(f"hourdiff is greater than 2 hours; adding 2 hours to {lstdt} for new max")
            hmax = lstts + 7200            
            mxdt = datetime.fromtimestamp(hmax)
            log.debug(f"New max timestamp is: {hmax}, aka {mxdt}")

        log.debug(f"Querying audit_log entries from {SID.upper()}")  
        getdata = f'''
                    select
                    "TIMESTAMP",
                    "HOST",
                    "PORT",
                    "SERVICE_NAME",
                    "CONNECTION_ID",
                    "CLIENT_HOST",
                    "CLIENT_IP",
                    "CLIENT_PID",
                    "CLIENT_PORT",
                    "USER_NAME",
                    "STATEMENT_USER_NAME",
                    "APPLICATION_NAME",
                    "APPLICATION_USER_NAME",
                    "XS_APPLICATION_USER_NAME",
                    "AUDIT_POLICY_NAME",
                    "EVENT_STATUS",
                    "EVENT_LEVEL",
                    "EVENT_ACTION",
                    "SCHEMA_NAME",
                    "OBJECT_NAME",
                    "PRIVILEGE_NAME",
                    "ROLE_SCHEMA_NAME",
                    "ROLE_NAME",
                    "GRANTEE_SCHEMA_NAME",
                    "GRANTEE",
                    "GRANTABLE",
                    "FILE_NAME",
                    "SECTION",
                    "KEY",
                    "PREV_VALUE",
                    "VALUE",
                    "STATEMENT_STRING",
                    "COMMENT",
                    "ORIGIN_DATABASE_NAME",
                    "ORIGIN_USER_NAME"
                    from "SYS"."AUDIT_LOG" 
                    where "TIMESTAMP" > \'{lstdt}\'
                    and "TIMESTAMP" <= \'{mxdt}\'
                '''
        try:
            cursor.execute(getdata)
            result = cursor.fetchall()
        except dbapi.Error as err:
            log.critical(f"HANA query to read audit_log was unsuccessful: {err}")
            status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'ERROR', 'UID': uniqid, 'QUERY' : getdata, 'DETAIL': err}
            log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
            testevent.flushBatch()
            return 1
        statcnt = len(result)
        log.info(f"Number of statistics returned: {statcnt}")  
        i = 0
        for row in result:
            dtz = row[0].replace(tzinfo=timezone.utc)
            dtt = dtz.timestamp()
            metrics = {}
            metrics['TIMESTAMP']=row[0]
            metrics['HOST']=row[1]
            metrics['PORT']=row[2]
            metrics['SERVICE_NAME']=row[3]
            metrics['CONNECTION_ID']=row[4]
            metrics['CLIENT_HOST']=row[5]
            metrics['CLIENT_IP']=row[6]
            metrics['CLIENT_PID'] = row[7]
            metrics['CLIENT_PORT'] = row[8]
            metrics['USER_NAME'] = row[9]
            metrics['STATEMENT_USER_NAME'] = row[10]
            metrics['APPLICATION_NAME'] = row[11]
            metrics['APPLICATION_USER_NAME'] = row[12]
            metrics['XS_APPLICATION_USER_NAME'] = row[13]
            metrics['AUDIT_POLICY_NAME'] = row[14]
            metrics['EVENT_STATUS'] = row[15]
            metrics['EVENT_LEVEL'] = row[16]
            metrics['EVENT_ACTION'] = row[17]
            metrics['SCHEMA_NAME'] = row[18]
            metrics['OBJECT_NAME'] = row[19]
            metrics['PRIVILEGE_NAME'] = row[20]
            metrics['ROLE_SCHEMA_NAME'] = row[21]
            metrics['ROLE_NAME'] = row[22]
            metrics['GRANTEE_SCHEMA_NAME'] = row[23]
            metrics['GRANTEE'] = row[24]
            metrics['GRANTABLE'] = row[25]
            metrics['FILE_NAME'] = row[26]
            metrics['SECTION'] = row[27]
            metrics['KEY'] = row[28]
            metrics['PREV_VALUE'] = row[29]
            metrics['VALUE'] = row[30]
            metrics['STATEMENT_STRING'] = row[31]
            metrics['COMMENT'] = row[32]
            metrics['ORIGIN_DATABASE_NAME'] = row[33]
            metrics['ORIGIN_USER_NAME'] = row[34]
            metrics['SID'] = SID.upper()
            metrics['EVENT_TYPE'] = "HANA_AUDIT"
            metrics['TIMESTAMP'] = dtz.strftime("%Y-%m-%d %H:%M:%S.%f %z")
            metrics['EVENT'] = "AUDIT ENTRY"
            metrics['UID'] = uniqid
            log_to_splunk(testevent, metrics, secret['hdbserver'], dtt, SID, log)
            i = i + 1
            log.debug(f"Inserted {i} records for {SID.upper()} into Splunk; last query time was {dtt} aka {dtz.strftime('%Y-%m-%d %H:%M:%S.%f %z')}")

        # Update logging table in HANA
        nowts = datetime.utcnow().timestamp()
        hourdiff = nowts - lstts
        log.debug(f"Hour diff between {nowts} and {lstts} is {hourdiff} seconds")
        log.debug(f"Inserting new MAX_TS of {mxdt} into {SID.upper()}")
        add_maxts = '''
                    INSERT into LAMBDAREMOTE.LAMBDA_CONTROL (LAMBDA, EXECUTION_TS, MAX_TS, STATUS) 
                    VALUES (:l, CURRENT_TIMESTAMP, :mts, :st)
                    '''
        try:
            cursor.execute(add_maxts, {"l": 'hana-audit', "mts": mxdt, "st": 'Success'})
            conn.commit()
        except dbapi.Error as err:
            log.debug(f"HANA query to update logging table was unsuccessful: {err}")
            return

    cursor.close()
    conn.close()

    # Log end of execution
    status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'END', 'UID': uniqid}
    log_to_splunk(testevent, status, secret['hdbserver'], time.time(), SID, log)
    # Flush the batch 
    log.debug(f"flushing the batch")
    testevent.flushBatch()

    log.debug(f"Script completed in {round(time.time() - start_time,2)} seconds\n\n")

def lastts(testevent, hdbserver, SID, cursor, log, uniqid):
    # Find the latest date/time of audit events already written to Splunk, from LAMBDA_CONTROL table
    find_lastts = '''
                select to_varchar(max(max_ts), 'YYYY-MM-DD HH24:MI:SS.FF6') 
                from LAMBDAREMOTE.LAMBDA_CONTROL
                where LAMBDA = 'hana-audit'
                and STATUS = 'Success'
                '''
    try:
        cursor.execute(find_lastts)
        lastts = cursor.fetchone()
    except dbapi.Error as err:
        log.error(f"HANA query to get last audit_log entry was unsuccessful: {err}")
        status = {'EVENT_TYPE': 'HANA_AUDIT', 'EVENT': 'ERROR', 'UID': uniqid, 'DETAIL': err}
        log_to_splunk(testevent, status, hdbserver, time.time(), SID, log)
        return
    # If no lastts[0], script has never been run; set to one week/month/year back
    if lastts[0] == None:
        x = datetime.utcnow().timestamp()
        y = x - 15768000 # 1 year: 31536000; 1 month: 2628000; 1 week: 588000
        ldt = datetime.fromtimestamp(y)
        lts = datetime.timestamp(ldt)
        log.debug(f"No last audit_log entry exists. Setting last to: {lts} aka {ldt}") 
    else:
        ldt = lastts[0]
        lts = datetime.strptime(ldt, '%Y-%m-%d %H:%M:%S.%f').timestamp()
        log.debug(f"Found last audit_log entry already sent to Splunk: {lts} aka {ldt}") 
    return (lts, ldt)

def maxts(testevent, hdbserver, SID, cursor, log, uniqid):
    # Find the latest timestamp which exists in audit_log view in HANA
    find_maxts = '''
                select to_varchar(max("TIMESTAMP"), 'YYYY-MM-DD HH24:MI:SS.FF6') 
                from SYS.AUDIT_LOG
                '''
    try:
        cursor.execute(find_maxts)
        maxts = cursor.fetchone()
    except dbapi.Error as err:
        log.error(f"HANA query to get max audit_log entry was unsuccessful: {err}")
        status = {'EVENT_TYPE': 'HANA_AUDIT',  'EVENT': 'ERROR', 'UID': uniqid, 'DETAIL': err}
        log_to_splunk(testevent, status, hdbserver, time.time(), SID, log)
        return
    if maxts[0] == None:
        # If there is no max, then there is no audit log entry so why are we even running this?
        # Set to something
        mdt = "2023-01-01 01:00:00"
        log.debug(f"Could not find max entry from audit_log; setting to: {mdt}")
    else:
        mdt = maxts[0]
        log.debug(f"Found max entry from audit_log: {mdt}")
    mts = datetime.strptime(mdt, '%Y-%m-%d %H:%M:%S.%f').timestamp()
    return (mts, mdt)

if __name__ == '__main__':
    SID = os.environ['SID']
    lambda_handler({"SID":SID},"dummy")