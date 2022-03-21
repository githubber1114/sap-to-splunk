import platform
import time
from hdbcli import dbapi

# Define connection to HANA
conn = dbapi.connect(
    key='<hdbuserstore entry>',
    encrypt='true',
    sslValidateCertificate='false'
)

cursor = conn.cursor()
sql_command = "select value from m_system_overview where name = 'Instance ID'"
start_time = time.time()
cursor.execute(sql_command)
rows = cursor.fetchall()
for row in rows:
    print (row[0])

print('query completed; Execution Time: {} secs'.format(time.time() - start_time))
print(len(rows), ' records returned')

cursor.close()
conn.close()
