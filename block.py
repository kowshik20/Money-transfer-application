from sha import *
import datetime
import pytz


def mine(a):
    nonce = 0
    modified_hash = a
    while modified_hash[:2] != "00": 
        nonce += 1
        modified_hash = a + str(nonce)  
        modified_hash = str(pinhash(modified_hash))

    return nonce, modified_hash


def time():
    indian_timezone = pytz.timezone('Asia/Kolkata')
    indian_time = datetime.datetime.now(indian_timezone)
    da = indian_time.strftime("%H%M%S")
    return da
