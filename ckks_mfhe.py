class MainServer:
  def __init__(self,data,username,userlist,writtendata):

    self.data = data
    self.username = username
    self.userlist = userlist
    self.writtendata = writtendata
  def write_in_server(self):
    if self.username in self.userlist:
      self.writtendata[self.username] = self.data
      return(self.writtendata)
    else:
      return('user not registered')
  def register(self):
    self.userlist.append(self.username)
    return(self.userlist)
  def readserverdata(self):
    return self.writtendata[self.username]

import time
from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_encoder import CKKSEncoder
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_parameters import CKKSParameters


import cProfile as cp

def set_timer_profile():
    pr = cp.Profile()
    pr.enable()
    start = time.time()
    return pr, start  

def end_timer_profile(pr, start, filename):
    cost = time.time() - start 
    pr.disable()
    pr.dump_stats(filename)
    return cost 


def CKKS_reg():
    poly_degree = 8
    ciph_modulus = 1 << 600
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    params = CKKSParameters(poly_degree=poly_degree,
                            ciph_modulus=ciph_modulus,
                            big_modulus=big_modulus,
                            scaling_factor=scaling_factor)
    key_generator = CKKSKeyGenerator(params)
    public_key = key_generator.public_key
    secret_key = key_generator.secret_key
    relin_key = key_generator.relin_key
    conj_key = key_generator.generate_conj_key()
    return params,public_key,secret_key,relin_key

def CKKS_encryption(mes_ar,params,pubkey,seckey,relinkey):
    poly_degree = 8
    ciph_modulus = 1 << 600
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    encoder = CKKSEncoder(params)
    encryptor = CKKSEncryptor(params, pubkey, seckey)
    decryptor = CKKSDecryptor(params, seckey)
    evaluator = CKKSEvaluator(params)
    plain = encoder.encode(mes_ar, scaling_factor)
    ciph = encryptor.encrypt_with_secret_key(plain)
    return ciph,evaluator

def CKKS_decryption(ciphtext,params,pubkey,seckey,relinkey):
    poly_degree = 8
    ciph_modulus = 1 << 600
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    encoder = CKKSEncoder(params)
    encryptor = CKKSEncryptor(params, pubkey, seckey)
    decryptor = CKKSDecryptor(params, seckey)
    evaluator = CKKSEvaluator(params)
    decrypted_text = decryptor.decrypt(ciphtext)
    decoded_text = encoder.decode(decrypted_text)
    return decoded_text

userdict = {}
cipdict = {}
ciphertext_modulus = 1 << 600
scaling_factor = 1 << 30
key_profile = 'py-fhe\profile\keygeneration.prof'
pr, start = set_timer_profile()
params1,public_key1,secret_key1,relin_key1 = CKKS_reg()
cost = end_timer_profile(pr,start,key_profile)
print('Key generation Done {0: .3f}s'.format(cost))

pr,start = set_timer_profile()
cipher1,eval1 = CKKS_encryption([5,2, 3,1],params1,public_key1,secret_key1,relin_key1) #message one
cost = end_timer_profile(pr,start,key_profile)
print('Encryption Done {0: .3f}s'.format(cost))

key_generator1 = CKKSKeyGenerator(params1)

rot_keys1 = {}

# Generate rotation keys for specific rotation angles and store them in rot_keys
for rotation_angle in range(params1.num_taylor_iterations):
    rotation_key = key_generator1.generate_rot_key(rotation_angle)
    rot_keys1[rotation_angle] = rotation_key


conj_key1 = key_generator1.generate_conj_key()
encoder1 = CKKSEncoder(params1)
userdict['user1'] = [params1,public_key1,secret_key1,relin_key1]
cipdict['user1'] = cipher1


params2,public_key2,secret_key2,relin_key2 = CKKS_reg()
cipher2,eval2 = CKKS_encryption([5,9, 3,1],params2,public_key2,secret_key2,relin_key2) #message 2
userdict['user2'] = [params2,public_key2,secret_key2,relin_key2]
cipdict['user2'] = cipher2


result = eval1.add(cipher1,cipher2)   #sum [5 2 3 1]+[5 9 3 1]
ciph_prod = eval1.multiply(cipher1, cipher2, relin_key1)    #product [5 2 3 1]*[5 9 3 1]


 
print(result)
print(CKKS_decryption(result,params1,public_key1,secret_key1,relin_key1))
print(CKKS_decryption(ciph_prod,params1,public_key1,secret_key1,relin_key1))




