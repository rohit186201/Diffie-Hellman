from client_encryption import EncryptionECDH as client_ecdh
from Encryption import EncryptionECDH as server_ecdh
import argparse

def DemoECDH(identity):
    client_encrypt = client_ecdh(identity)
    client_public_key = client_encrypt.extractPublicKey()
    print("\n\ngenerating public key and private key for client to send it to server"
            " ..........\n\n")

    print("Generated keys for {0}\npublic_key [{1}]\nprivate_key [{2}]\n\n"
            .format(identity, client_encrypt.extractPublicKey(),
                client_encrypt.extractSecretKey()))

    print("\n\nSending client public key to server"
            " ..........\n\n")

    server_encrypt = server_ecdh("Server", client_public_key) #client public key
    server_public_key = server_encrypt.extractPublicKey()
    print("Server says:\n\nReceived client_pub_key = {0}\n\nMy Own keys are:\npublic_key [{1}]\nprivate_key [{2}]\nshared_secret_key [{3}]\n\n"
            .format(client_public_key,
                server_encrypt.extractPublicKey(),
                server_encrypt.extractSecretKey(),
                server_encrypt.extractSharedKey()))

    print("\n\n{0} says:\n\nReceived server public key [{1}] Now Let me calculete my shared secret key.......\n"
            .format(identity, server_public_key))

    # client side
    client_shared_secretkey = client_encrypt.secretGeneration(identity, server_encrypt.extractPublicKey())
    print("calculated shared secret for {0} = [{1}]\n\n"
            .format(identity, client_encrypt.extractSharedKey()))

    # test shared secret key values
    if server_encrypt.extractSharedKey() == client_encrypt.extractSharedKey():
        print("Test PASSED......")
    else:
        print("Test Failed !!!!! Different shared secret generated {0} {1}"
                .format(server_encrypt.extractSharedKey(), client_encrypt.extractSharedKey()))


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--identity",type=str,help="--identity for specifying client's identity")
    args=parser.parse_args()
    if args.identity:
        DemoECDH(args.identity)
    else:
        print("ERROR Give identity as --identity=<identity>")
