'''
Author: Tarit Goswami
Organization: Jalpaiguri Govt. Engineering College
              Jalpaiguri, WB, India
License: MIT license

This program encrypts messages and decrypts encrypted messages using ElGamal
encryption and decryption algorithm. Before encrypting the message, we are 
padding the message using OAEP padding. We have used BLAKE2b hashing function.
'''
from hashlib import blake2b
import binascii
import random
import string
from math import pow
import time
global st,et
a = random.randint(2, 10)

# st=time.process_time_ns()
def xor_strings(xs,ys):
    
    return "".join(chr(ord(x)^ ord(y)) for x,y in zip(xs,ys))

def ASCII(s):
    x = 0
    for i in range(len(s)):
        x += ord(s[i])*2**(8 * (len(s) - i - 1))
    return x

def padded(msg,r,t):
    global X,Y
    
    msg=msg+t
    
    h=blake2b(r.encode('utf-8')).hexdigest()
    
    X=xor_strings(msg,h)
    
    g=blake2b(X.encode('utf-8')).hexdigest()
    
    Y=xor_strings(r,g)
    
    mn=hex(ASCII(X)| ASCII(Y))
    
    return mn

def unpadded(X,Y):   
    r1=xor_strings(Y,blake2b(X.encode('utf-8')).hexdigest())
    
    mn=xor_strings(X,blake2b(r1.encode('utf-8')).hexdigest())
    
    return mn

def randomString2(length=8):
    letters=string.ascii_lowercase
    
    test_str=''.join(random.sample(letters,length))
    
    res = ''.join(format(ord(i), 'b') for i in test_str)
    
    return(str(res))


def gcd(a, b):
    if a < b: 
        return gcd(b, a) 
    elif a % b == 0: 
        return b; 
    else: 
        return gcd(b, a % b)

# Generating large random number

def gen_key(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q) 
    return key 

# Modular exponentiation

def power(a, b, c):
    x = 1
    y = a 

    while b > 0: 
            if b % 2 == 0: 
                    x = (x * y) % c; 
            y = (y * y) % c 
            b = int(b / 2) 

    return x % c 

# Asymmetric encryption

def encrypt(X,Y, q, h, g):

    en_msg = []
    en_msg1 =[]

    k = gen_key(q)# Private key for sender 
    s = power(h, k, q) 
    p = power(g, k, q)

    for i in range(0, len(X)): 
            en_msg.append(X[i])
    for i in range(0, len(Y)): 
            en_msg1.append(Y[i])        
            
    #print("g^k used : ", p) 
    #print("g^ak used : ", s) 
    for i in range(0, len(en_msg)): 
            en_msg[i] = s * ord(en_msg[i])
    for i in range(0, len(en_msg)): 
            en_msg1[i] = s * ord(en_msg1[i])        

    return en_msg, en_msg1,p 

def decrypt(emsg1,emsg2, p, key, q):

    dr_msg = []
    dr_msg1 = []
    h = power(p, key, q) 
    for i in range(0, len(emsg1)): 
            dr_msg.append(chr(int(emsg1[i]/h)))
    
    dr_msg = ''.join(dr_msg)
    for i in range(0, len(emsg1)): 
            dr_msg1.append(chr(int(emsg2[i]/h)))
    dr_msg1 = ''.join(dr_msg1)        
    
    return dr_msg,dr_msg1

if __name__ == '__main__':
    
    msg=g = input("Enter your message: ")
    t='000000000'
    r=randomString2()
    
    print('Original Message:',msg)
    pd=padded(msg,r,t)
    print('Padded text:',pd)

    q = random.randint(pow(10, 20), pow(10, 50)) 
    g = random.randint(2, q) 

    key = gen_key(q)# Private key for receiver 
    h = power(g, key, q) 
    #print("g used : ", g) 
    #print("g^a used : ", h) 

    en_msg, en_msg1,p = encrypt(X,Y,q, h, g)
    print('Encrypted X:',type(en_msg))
    print('Encrypted Y:',type(en_msg1))

    dr_msg,dr_msg1 = decrypt(en_msg,en_msg1, p, key, q)
    print('DEncrypted X:',type(dr_msg))
    print('DEncrypted Y:',type(dr_msg1))
    
    print('After unpadding:',unpadded(X,Y).strip(t))

    # et=time.process_time_ns()
    # print('The program executes in:',et-st)
