import eddsa

def hashing(m):
    return eddsa.hashing(str(m))

def hash_x_and_q(x,q):  # user will call this function once for each MIA
    y=hashing(x+q)
    return y
