
import json
import os
import threading
import time

lock = threading.Lock()

hashing_method = None
totp_status = None
using_captcha=None
locking_user_status=None
is_rate_limiting=None

#setting up all the global parameters that will be written as config files
def setup():
    global hashing_method
    hashing_method = os.getenv('SECURITY')
    global totp_status
    totp_status = os.getenv('MFA_on')
    global using_captcha
    using_captcha = os.getenv('CAPTCHA_ON')
    global locking_user_status
    locking_user_status = os.getenv('IS_LOCKING')
    global is_rate_limiting
    is_rate_limiting = os.getenv('IS_RATE_LIMITING')

#creating the json file from the given user parameters
def write_log(username,start_time,route,status,res_json):
    global hashing_method
    global totp_status
    global using_captcha
    global locking_user_status
    global is_rate_limiting

    #calculating latency
    end_time = time.time()
    total_time = end_time - start_time

    #creating a readable start time
    start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    #extracting the fail reason from the res_json
    fail_reason = (json.loads(res_json)).get('reason',"None")
    #creating the json log
    json_str = json.dumps({"route":route,
                           "status_code":status,
                           "username":username,
                           "fail_reason":fail_reason,
                           "start_time":start_time_readable,
                           "total_time":total_time,
                           "configuration":
                               {
                                   "hashing_method": hashing_method,
                                   "totp_status": totp_status,
                                   "using_captcha": using_captcha,
                                   "locking_user_status": locking_user_status,
                                   "is_rate_limiting": is_rate_limiting
                               }
                           },ensure_ascii=False)
    write_to_log_file(json_str)

#writing the log record to the file
def write_to_log_file(json_record):
    with lock:
        with open("log.jsonl",'a',encoding="utf-8") as log_file:
            log_file.write(json_record+"\n")
