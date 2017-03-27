from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET

if __name__ == '__main__':
    tree = ET.parse('../conf/miner_discovery.xml')
    root = tree.getroot()
    miners = root.find('miners')

    #FIXME remove the existing keys if the setup was already done

    for miner in miners:
        # generate private/public key pair
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)

        # get public key in OpenSSH format
        public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

        # get the private key in PEM format
        pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())

        pub_key_xml = ET.Element('pub_key')
        pub_key_xml.text = public_key.decode()[8:]
        miner.append(pub_key_xml)

        file = open("../keys/miner" + miner.get('id') + ".key", 'w')
        file.write(pem.decode())
        file.close()
    tree.write('../conf/miner_discovery.xml')

