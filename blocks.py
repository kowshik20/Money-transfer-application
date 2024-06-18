import sqlite3
import json


conn = sqlite3.connect('transfer_details.db') 
cursor = conn.cursor()
cursor.execute("SELECT * FROM transfer_records")
rows = cursor.fetchall()
data = []
for row in rows:
    record = {
        'id': row[0],
        'users_name': row[1],
        'users_email': row[2],
        'recipients_username': row[3],
        'timestamp': row[4],
        'amount': row[5],
        'previous_hash': row[6],
        'hash': row[7],
        'nonce': row[8],
        'modified_hash': row[9]
    }
    data.append(record)

json_data = json.dumps(data, indent=4)
print(json_data)
cursor.close()
conn.close()
