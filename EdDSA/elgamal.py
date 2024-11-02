from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal

cipher_elg = ElGamal(Curve25519)

# plaintext = b"I am plaintext."
def generate_keys():
    PK, SK = gen_keypair(Curve25519)   # public key, secret key of the user Ui
    return (PK,SK)

def encrypt(m,PK):
    c1, c2, r = cipher_elg.encrypt(m,PK)
    return (c1, c2, r)

def decrypt(SK,c1,c2):
    m = cipher_elg.decrypt(SK, c1, c2)
    return m;

def test():
    sk, pk = generate_keys()
    # m = eddsa.textToInt("Buri buri zaemon ka khajana")
    m = b"Buri buri zaemon ka khajana"
    cp1, cp2, r = encrypt(m,pk)
    print("r: ", r)
    print("cp1: ",cp1) 
    print("cp2: ",cp2) 
    saxsux = decrypt(sk,cp1,cp2)
    print(saxsux)

test()
