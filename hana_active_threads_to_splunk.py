import platform
import time
from hdbcli import dbapi
import json
import requests
import urllib3
urllib3.disable_warnings()

# Define connection to HANA
conn = dbapi.connect(
    key='<hdbuserstore entry>',
    encrypt='true',
    sslValidateCertificate='false'
)

cursor = conn.cursor()
sql_command = """
                    SELECT
                      NOW(),
                      "THREADS"."HOST" AS HOST,
                      "THREADS"."PORT" AS PORT,
                      "THREADS"."SERVICE_NAME" AS SERVICE_NAME,
                      "THREADS"."HIERARCHY" AS HIERARCHY,
                      "THREADS"."CONNECTION_ID" AS CONNECTION_ID,
                      "THREADS"."THREAD_ID" AS THREAD_ID,
                      "THREADS"."THREAD_TYPE" AS THREAD_TYPE,
                      "THREADS"."THREAD_METHOD" AS THREAD_METHOD,
                      "THREADS"."THREAD_DETAIL" AS THREAD_DETAIL,
                      "THREADS"."DURATION" AS DURATION,
                      "THREADS"."CALLER" AS CALLER,
                      "THREADS"."CALLING" AS CALLING,
                      "THREADS"."USER_NAME" AS USER_NAME,
                      "THREADS"."APPLICATION_USER_NAME" AS APPLICATION_USER_NAME,
                      "THREADS"."CPU_TIME_SELF" AS CPU_TIME_SELF,
                      "THREADS"."CPU_TIME_CUMULATIVE" AS CPU_TIME_CUMULATIVE,
                      "THREADS"."THREAD_STATE" AS THREAD_STATE,
                      "THREADS"."TRANSACTION_ID" AS T5_TRANSACTION_ID,
                      "THREADS"."UPDATE_TRANSACTION_ID" AS UPDATE_TRANSACTION_ID,
                      "CONN"."TRANSACTION_ID" AS T6_TRANSACTION_ID,
                      "CONN"."START_TIME" AS START_TIME,
                      "CONN"."IDLE_TIME" AS IDLE_TIME,
                      "CONN"."CONNECTION_STATUS" AS CONNECTION_STATUS,
                      "CONN"."CLIENT_HOST" AS CLIENT_HOST,
                      "CONN"."CLIENT_IP" AS CLIENT_IP,
                      "CONN"."CLIENT_PID" AS CLIENT_PID,
                      "CONN"."CONNECTION_TYPE" AS CONNECTION_TYPE,
                      "CONN"."OWN" AS OWN,
                      "CONN"."IS_HISTORY_SAVED" AS IS_HISTORY_SAVED,
                      "CONN"."MEMORY_SIZE_PER_CONNECTION" AS MEMORY_SIZE_PER_CONNECTION,
                      "CONN"."AUTO_COMMIT" AS AUTO_COMMIT,
                      "CONN"."LAST_ACTION" AS LAST_ACTION,
                      "CONN"."CURRENT_STATEMENT_ID" AS CURRENT_STATEMENT_ID,
                      "CONN"."CURRENT_OPERATOR_NAME" AS CURRENT_OPERATOR_NAME,
                      "CONN"."FETCHED_RECORD_COUNT" AS FETCHED_RECORD_COUNT,
                      "CONN"."SENT_MESSAGE_SIZE" AS SENT_MESSAGE_SIZE,
                      "CONN"."SENT_MESSAGE_COUNT" AS SENT_MESSAGE_COUNT,
                      "CONN"."RECEIVED_MESSAGE_SIZE" AS RECEIVED_MESSAGE_SIZE,
                      "CONN"."RECEIVED_MESSAGE_COUNT" AS RECEIVED_MESSAGE_COUNT,
                      "CONN"."CREATOR_THREAD_ID" AS CREATOR_THREAD_ID,
                      "CONN"."CREATED_BY" AS CREATED_BY,
                      "CONN"."IS_ENCRYPTED" AS IS_ENCRYPTED,
                      "CONN"."END_TIME" AS END_TIME,
                      "BLOCKED"."BLOCKED_TRANSACTION_ID" AS BLOCKED_TRANSACTION_ID,
                      "BLOCKED"."BLOCKED_UPDATE_TRANSACTION_ID" AS BLOCKED_UPDATE_TRANSACTION_ID,
                      "BLOCKED"."LOCK_OWNER_TRANSACTION_ID" AS LOCK_OWNER_TRANSACTION_ID,
                      "BLOCKED"."LOCK_OWNER_UPDATE_TRANSACTION_ID" AS LOCK_OWNER_UPDATE_TRANSACTION_ID,
                      "BLOCKED"."BLOCKED_TIME" AS BLOCKED_TIME,
                      "BLOCKED"."WAITING_RECORD_ID" AS WAITING_RECORD_ID,
                      "BLOCKED"."WAITING_SCHEMA_NAME" AS WAITING_SCHEMA_NAME,
                      "BLOCKED"."LOCK_TYPE" AS LOCK_TYPE,
                      "BLOCKED"."LOCK_MODE" AS LOCK_MODE,
                      "TRANS1"."HOST" AS T1_HOST,
                      "TRANS1"."PORT" AS T1_PORT,
                      "TRANS1"."TRANSACTION_ID" AS T1_TRANSACTION_ID,
                      "TRANS2"."TRANSACTION_ID" AS T2_TRANSACTION_ID,
                      "TRANS3"."CONNECTION_ID" AS T3_CONNECTION_ID,
                      "TRANS4"."HOST" AS T4_HOST,
                      "TRANS4"."PORT" AS T4_PORT,
                      "TRANS4"."TRANSACTION_ID" AS T4_TRANSACTION_ID,
                      "TRANS4"."CONNECTION_ID" AS T4_CONNECTION_ID,
                      "BLOCKED"."WAITING_OBJECT_NAME" AS WAITING_OBJECT_NAME,
                      "BLOCKED"."WAITING_OBJECT_TYPE" AS WAITING_OBJECT_TYPE,
                      "THREADS"."LOCK_WAIT_COMPONENT" AS LOCK_WAIT_COMPONENT,
                      "THREADS"."LOCK_WAIT_NAME" AS LOCK_WAIT_NAME,
                      "THREADS"."LOCK_OWNER_THREAD_ID" AS LOCK_OWNER_THREAD_ID,
                      "THREADS"."STATEMENT_HASH" AS STATEMENT_HASH ,
                      "THREADS"."APPLICATION_NAME" AS APPLICATION_NAME  ,
                      "THREADS"."APPLICATION_SOURCE" AS APPLICATION_SOURCE  ,
                      "THREADS"."STATEMENT_ID" AS STATEMENT_ID  ,
                      "THREADS"."LOCKS_OWNED" AS LOCKS_OWNED ,
                      "THREADS"."PRIORITY" AS PRIORITY,
                      "THREADS"."STATEMENT_THREAD_LIMIT" AS STATEMENT_THREAD_LIMIT ,
                      "THREADS"."STATEMENT_MEMORY_LIMIT" AS STATEMENT_MEMORY_LIMIT 
                    FROM PUBLIC.M_SERVICE_THREADS AS THREADS
                      LEFT OUTER JOIN M_CONNECTIONS AS CONN ON THREADS.CONNECTION_ID = CONN.CONNECTION_ID
                      LEFT OUTER JOIN M_BLOCKED_TRANSACTIONS AS BLOCKED ON CONN.TRANSACTION_ID = (
                        SELECT
                          TRANSACTION_ID 
                        FROM M_TRANSACTIONS 
                        WHERE UPDATE_TRANSACTION_ID = BLOCKED.BLOCKED_UPDATE_TRANSACTION_ID
                          AND TRANSACTION_TYPE = 'USER TRANSACTION') 
                      LEFT OUTER JOIN M_TRANSACTIONS AS TRANS1 ON (
                        TRANS1.UPDATE_TRANSACTION_ID = BLOCKED.LOCK_OWNER_UPDATE_TRANSACTION_ID
                        AND TRANS1.TRANSACTION_TYPE = 'USER TRANSACTION')
                      LEFT OUTER JOIN M_TRANSACTIONS AS TRANS2 ON (
                        TRANS2.UPDATE_TRANSACTION_ID = BLOCKED.BLOCKED_UPDATE_TRANSACTION_ID
                        AND TRANS2.TRANSACTION_TYPE = 'USER TRANSACTION')
                      LEFT OUTER JOIN M_TRANSACTIONS AS TRANS3 ON (
                        TRANS3.UPDATE_TRANSACTION_ID = BLOCKED.LOCK_OWNER_UPDATE_TRANSACTION_ID
                        AND TRANS3.HOST = BLOCKED.HOST
                        AND TRANS3.TRANSACTION_ID = BLOCKED.LOCK_OWNER_TRANSACTION_ID
                        AND TRANS3.TRANSACTION_TYPE = 'EXTERNAL TRANSACTION')
                      LEFT OUTER JOIN M_TRANSACTIONS AS TRANS4 ON (
                        TRANS4.UPDATE_TRANSACTION_ID = BLOCKED.BLOCKED_UPDATE_TRANSACTION_ID
                        AND TRANS4.TRANSACTION_ID = BLOCKED.BLOCKED_TRANSACTION_ID
                        AND TRANS4.HOST = BLOCKED.HOST 
                        AND TRANS4.PORT = BLOCKED.PORT
                        AND TRANS4.TRANSACTION_TYPE = 'EXTERNAL TRANSACTION') 
                    WHERE THREAD_STATE != 'Inactive' 
                      AND THREAD_DETAIL NOT LIKE '%M_SERVICE_THREADS%'
                    FOR JSON
"""
start_time = time.time()
cursor.execute(sql_command)
result = cursor.fetchall()
for row in result:
    json_res = json.loads(row[0])
    for i in range(len(json_res)):
        json_res[i]['EVENT_TYPE'] = 'ACTIVE_THREADS'
        splunk_dict = {"index":"<splunk index name>", "event": json_res[i] }
        #splunk url eg: url='https://<hec-server-name>/services/collector/event'
        url='<splunk url>'
        authHeader = {'Authorization': 'Splunk {}'.format('<splunk token>')}
        r = requests.post(url, headers=authHeader, json=splunk_dict, verify=False)
        print('Inserting into Splunk status:')
        print(r.text)

cursor.close()
conn.close()
