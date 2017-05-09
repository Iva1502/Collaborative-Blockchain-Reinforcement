from Crypto.PublicKey import RSA
from constants import CANCEL_BLOCK_MIN_RANGE, CANCEL_BLOCK_MAX_RANGE, PORT
import json
import argparse
import random
from pathlib import Path


if __name__ == '__main__':
    default_value = [5, 2, 2]
    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(usage='''setup.py [-a, n_miners n_malicious n_clients]''')
    parser.add_argument("-a", "--all", nargs=3, type=int, default=default_value)
    args = parser.parse_args()

    my_file = Path("../conf/miner_discovery.json")
    if my_file.is_file():
        with open('../conf/miner_discovery.json', 'r') as file:
            data = json.load(file)
            if args.all == default_value:
                args.all = None
    else:
        data = {}

    port = PORT
    data['cancel_block'] = random.randint(CANCEL_BLOCK_MIN_RANGE, CANCEL_BLOCK_MAX_RANGE)

    if args.all is not None:
        data['miners'] = []
        for miner_id in range(1, args.all[0] + 1):
            miner_data = {}

            # generate private/public key pair
            key = RSA.generate(1024)
            private_key = key
            public_key = key.publickey()
            file = open("../keys/miners/miner" + str(miner_id) + ".key", 'wb')
            file.write(private_key.exportKey('PEM'))
            file.close()

            # edit the configuration file
            miner_data['id'] = miner_id
            miner_data['port'] = str(port + miner_id)
            miner_data['pub_key'] = public_key.exportKey('OpenSSH').decode()
            miner_data['malicious'] = args.all[1] > 0
            args.all[1] -= 1
            data['miners'].append(miner_data)

        data['clients'] = []
        for client_id in range(1, args.all[2] + 1):
            client_data = {}

            # generate private/public key pair
            key = RSA.generate(1024)
            private_key = key
            public_key = key.publickey()
            file = open("../keys/clients/client" + str(client_id) + ".key", 'wb')
            file.write(private_key.exportKey('PEM'))
            file.close()
            client_data['pub_key'] = public_key.exportKey('OpenSSH').decode()

            # edit the configuration file
            client_data['id'] = client_id
            client_data['port'] = str(port + args.all[0] + client_id)
            client_data['pub_key'] = public_key.exportKey('OpenSSH').decode()
            data['clients'].append(client_data)

    file = open('../conf/miner_discovery.json', 'w')
    json.dump(data, file, indent=4)
