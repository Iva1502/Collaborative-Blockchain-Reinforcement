from Crypto.PublicKey import RSA
import json

if __name__ == '__main__':
    file = open('../conf/miner_discovery.json', 'r')
    data = json.load(file)

    for miner in data['miners']:
        # generate private/public key pair
        key = RSA.generate(1024)

        private_key = key
        public_key = key.publickey()

        miner['pub_key'] = public_key.exportKey('OpenSSH').decode()

        file = open("../keys/miner" + str(miner['id']) + ".key", 'wb')
        file.write(private_key.exportKey('PEM'))
        file.close()

    file = open('../conf/miner_discovery.json', 'w')
    json.dump(data, file, indent=4)
