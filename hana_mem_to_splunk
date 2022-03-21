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
                    select 
                    "SNAPSHOT_ID",
                    "SERVER_TIMESTAMP",
                    "ALLOCATION_LIMIT",
                    "FREE_PHYSICAL_MEMORY",
                    "FREE_SWAP_SPACE",
                    "HOST",
                    "INSTANCE_CODE_SIZE",
                    "INSTANCE_SHARED_MEMORY_ALLOCATED_SIZE",
                    "INSTANCE_TOTAL_MEMORY_ALLOCATED_SIZE",
                    "INSTANCE_TOTAL_MEMORY_USED_SIZE",
                    "TOTAL_CPU_IDLE_TIME",
                    "TOTAL_CPU_SYSTEM_TIME",
                    "TOTAL_CPU_USER_TIME",
                    "TOTAL_CPU_WIO_TIME",
                    "USED_PHYSICAL_MEMORY",
                    "USED_SWAP_SPACE",
                    "OPEN_FILE_COUNT",
                    "ACTIVE_ASYNC_IO_COUNT",
                    "INSTANCE_TOTAL_MEMORY_PEAK_USED_SIZE",
                    "SYS_TIMESTAMP",
                    "UTC_TIMESTAMP"
                     from "_SYS_STATISTICS"."HOST_RESOURCE_UTILIZATION_STATISTICS_BASE"
                     where"SERVER_TIMESTAMP" = (select max("SERVER_TIMESTAMP")
                     from "_SYS_STATISTICS"."HOST_RESOURCE_UTILIZATION_STATISTICS_BASE")
                    FOR JSON
"""
start_time = time.time()
cursor.execute(sql_command)
result = cursor.fetchall()
for row in result:
    json_res = json.loads(row[0])
    for i in range(len(json_res)):
        json_res[i]['EVENT_TYPE'] = 'HANA_MEM'
        splunk_dict = {"index":"<splunk index name>", "event": json_res[i] }
        #splunk url eg: url='https://<hec-server-name>/services/collector/event'
        url='<splunk url>'
        authHeader = {'Authorization': 'Splunk {}'.format('<splunk token>')}
        r = requests.post(url, headers=authHeader, json=splunk_dict, verify=False)
        print('Inserting into Splunk status:')
        print(r.text)

cursor.close()
conn.close()
