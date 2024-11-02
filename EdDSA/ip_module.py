import json
import eddsa
import hashlib


p = eddsa.p
base = eddsa.base
a = eddsa.a; d =(((-121665)%p * (eddsa.findModInverse(121666, p))%p)%p+p)%p #ed25519

def get_ei(pia):
    ei = eddsa.applyDoubleAndAddMethod(base, pia, a, d, p)
    return ei

def register(Xt,h):
    f = open('secret_data.json', 'r+')
    data = json.load(f)
    for key in data:
        if(key==h):
            print("Ae dusra number daal")
            return
    pia = Xt[0]
    ei = get_ei(pia)
    data[str(ei)]=pia
    f.seek(0)
    json.dump(data, f, indent = 4)
    f.close()
    sign_cert(Xt,h)

def sign_cert(Xt,h):
    root = int(hashlib.sha256(bytes(h)).hexdigest(), 16)
    # for i in range [0, 4]:
    #     root = root^hashlib.sha256(Xt[i])
    print(root)
    temp = (int((hashlib.sha256(bytes(Xt))).hexdigest(), 16))
    print(temp)
    root = root^temp
    
    # root = hashlib.sha256((str(Xt)+str(h)).encode("utf-8")).hexdigest()  # root = H(Xt,h)
    # cert = eddsa.sign_message(root)  # cert = sign(root, SK_IP) , SK_IP is in eddsa.py
    print(root)
    # return cert

sign_cert(0, 1)
# register(0, 0)