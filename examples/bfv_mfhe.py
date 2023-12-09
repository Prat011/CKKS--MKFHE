from bfv.batch_encoder import BatchEncoder
from bfv.bfv_decryptor import BFVDecryptor
from bfv.bfv_encryptor import BFVEncryptor
from bfv.bfv_evaluator import BFVEvaluator
from bfv.bfv_key_generator import BFVKeyGenerator
from bfv.bfv_parameters import BFVParameters



def Keygen():

    degree = 2
    # Ciphertext modulus is a prime congruent to 1 (mod 16).
    plain_modulus = 17
    ciph_modulus = 8000000000000
    params = BFVParameters(poly_degree=degree,
                           plain_modulus=plain_modulus,
                           ciph_modulus=ciph_modulus)
    key_generator = BFVKeyGenerator(params)
    public_key = key_generator.public_key
    secret_key = key_generator.secret_key
    relin_key = key_generator.relin_key
    return params,secret_key,public_key,relin_key

def encryption(params,secret_key,public_key,plain1):
    encoder = BatchEncoder(params)
    encryptor = BFVEncryptor(params, public_key)
    decryptor = BFVDecryptor(params, secret_key)
    evaluator = BFVEvaluator(params)
    plain1 = encoder.encode(message1)
    ciph1 = encryptor.encrypt(plain1)

    return ciph1, decryptor,evaluator,encoder


message1 = [5,1]
message2 = [8,6]

params1,secret_key1,public_key1,relin_key1 = Keygen()
params2,secret_key2,public_key2,relin_key2 = Keygen()

ciph1,decryptor1,eval1,encoder1 = encryption(params1,secret_key1,public_key1,message1)
ciph2,decryptor2,eval2,encoder2 = encryption(params2,secret_key2,public_key2,message2)

ciph_prod = eval1.add(ciph1, ciph2)
decrypted_prod = decryptor1.decrypt(ciph_prod)
decoded_prod = encoder1.decode(decrypted_prod)
    
print(decoded_prod)

ciph_prod = eval2 .add(ciph1, ciph2)
decrypted_prod = decryptor2.decrypt(ciph_prod)
decoded_prod = encoder2.decode(decrypted_prod)
    
print(decoded_prod)
