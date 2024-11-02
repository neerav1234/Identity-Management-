def findModInverse(A, M):
    X = pow(A, -1, M)
    if(not isinstance(X, int)):
       print(type(X))
    return X

# ###########################################
p = pow(2, 255) - 19
base = 15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960
a = -1; d =(((-121665)%p * (findModInverse(121666, p))%p)%p+p)%p #ed25519

def pointAddition(P, Q, a, d, mod):
   x1 = P[0]; y1 = P[1]; x2 = Q[0]; y2 = Q[1]
   x3 = (((x1*y2 + y1*x2) % mod) * findModInverse(1+d*x1*x2*y1*y2, mod)) % mod
   y3 = (((y1*y2 - a*x1*x2) % mod) * (findModInverse(1- d*x1*x2*y1*y2, mod)) % mod)
   return x3, y3

def applyDoubleAndAddMethod(P, k, a, d, mod):
   additionPoint = (P[0], P[1])
   kAsBinary = bin(k) #0b1111111001
   kAsBinary = kAsBinary[2:len(kAsBinary)] #1111111001
   #print(kAsBinary)
 
   for i in range(1, len(kAsBinary)):
      currentBit = kAsBinary[i: i+1]
      #always apply doubling
      additionPoint = pointAddition(additionPoint, additionPoint, a, d, mod)
 
      if currentBit == '1':
         #add base point
         additionPoint = pointAddition(additionPoint, P, a, d, mod)
 
   return additionPoint
   
######################## key generation #####################

privateKey =  35298574756525167146854357576934374334551015136372359992504602376187805335139 # 256 bit secret key
publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p)

######################## signing ############################
def textToInt(text):
   encoded_text = text.encode('utf-8')
   hex_text = encoded_text.hex()
   int_text = int(hex_text, 16)
   return int_text
 
def hashing(message):
   import hashlib
   return int(hashlib.sha256(str(message).encode("utf-8")).hexdigest(), 16)

def sign_message(message):
    message = textToInt(message)
    r = hashing(hashing(message) + message) % p
    R = applyDoubleAndAddMethod(base, r, a, d, p)
    h = hashing(R[0] + publicKey[0] + message) % p
    s = (r + h * privateKey)
    print("R:",R)
    print("s:",s)
    return (R,s)

####################### verifying ########################
# h = hashing(R[0] + publicKey[0] + message) % p
# P1 = applyDoubleAndAddMethod(base, s, a, d, p)
# P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h, a, d, p), a, d, p)
# if(P1==P2):
#    print("Arre mithai toh batwao")
# else:
#    print("Fail ho gye ho sahibzaade")

