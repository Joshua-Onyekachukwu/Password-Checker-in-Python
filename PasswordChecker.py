import hashlib
import requests
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Something went wrong: {res.status_code}, check the API and Try Again')
    return res


# def read_res(response):
#     print(response.text)

def get_pass(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hashes, count in hashes:
        if hashes == hash_to_check:
            return count
    return 0
        # print(hashes, count)

def pwned_api_check(password):
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_pass(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Your Password {password} was found {count} time..... You should change it!')
        else:
            print(f'{password} was NOT FOUND')
    return 'Done'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))



