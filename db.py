import sqlite3
import re
from md5 import *
from sha import *
import random
from datetime import datetime, timezone, timedelta

def validate_email_domain(email):
    pattern = r'^[a-zA-Z0-9._-]+@gmail\.com$'
    return re.match(pattern, email)



# Function to get Indian Standard Time (IST)
def get_indian_time():
    utc_now = datetime.utcnow()    
    ist_offset = timedelta(hours=5, minutes=30)
    ist_now = utc_now + ist_offset
    return ist_now

def create_users_table():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            amount Integer NOT NULL,
            pin TEXT -- Adding a column for pin
        )
    ''')
    conn.commit()
    conn.close()

def transaction_table():
    conn = sqlite3.connect('transfer_details.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS transfer_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    users_name TEXT,
                    users_email TEXT,
                    recipients_username TEXT,
                    timestamp TEXT,
                    amount INTEGER,
                    previous_hash TEXT,
                    hash TEXT,
                    nonce INTEGER,
                    modified_hash TEXT
                   )
                ''')

    conn.commit()
    conn.close()


create_users_table() 
transaction_table()
