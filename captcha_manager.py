import json
import os
import uuid
CAPTCHA_THRESHOLD = 7

failed_attempts_counter={} #ip:number_of_counts
valid_captcha_codes={}#ip:code

#updates the number of failed authentication in row per ip
def update_password_failed_attempts(ip):
    count = failed_attempts_counter.get(ip)
    if count is None:
        failed_attempts_counter[ip]=1
    elif 0<count < CAPTCHA_THRESHOLD:
        failed_attempts_counter[ip]+=1
    return count

#update the end of failed authentication in a raw
def update_successful_login_attempts(ip):
    del failed_attempts_counter[ip]

#checks if a captcha is required for this ip
def captcha_required(ip):

    count = failed_attempts_counter.get(ip)
    #too much failed attempts
    if count >= CAPTCHA_THRESHOLD:
        return True
    return False

#testing the given group seed and if it's correct generating
#a captcha answer
def captcha_gen(ip,tested_group_seed):
    #ip doesn't requird a captcha test
    if not captcha_required(ip):
        return json.dumps({"status": "failed","reason":"captcha is not required"})

    #comparing group seeds
    if not tested_group_seed == os.getenv('GROUP_SEED'):
        return json.dumps({"status": "failed","reason":"wrong group seed"})

    #generating answer
    captcha_code = uuid.uuid4().hex
    valid_captcha_codes[ip]=captcha_code
    return json.dumps({"status": "ok","reason":"none","captcha_code":captcha_code})

#validating the captcha attempt for the ip
def validate_captcha_code(ip,captcha_code):

    #comparing the correct answer with the given on this ip
    current_captcha_code=valid_captcha_codes.get(ip)
    if current_captcha_code is None or current_captcha_code!=captcha_code:
        return False,json.dumps({"status": "failed","reason":"invalid captcha code"})
    del valid_captcha_codes[ip]
    return True,json.dumps({"status": "ok","reason":"none"})



