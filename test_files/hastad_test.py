from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import Hastad
from Crypto.PublicKey import RSA
import sys

sys.setrecursionlimit(10000)

# Parse and store all of the ciphertexts provided by the file
rsadata_list = []
c = None
e = None
N = None
f = open("hastadlist.txt", 'r')
for line in f:
	if line.startswith("e"):
		e = long(line.split(" ")[2])
	elif line.startswith("n"):
		N = long(line.split(" ")[2], 0)
	elif line.startswith("ciphertext"):
		c = long(line.split(" ")[2], 0)
		rsadata_list.append(RSAData(rsa_obj(N, e), TextData(c, 1)))
f.close()

# Run the exploit by specifying it
if Hastad().run(rsadata_list):		
    print num2string(rsadata_list[0].get_m())

print "----------------------------------------------------"

# Run list of exploits
rsa_cracker.init()
if rsa_cracker.attack(rsadata_list):
    print num2string(rsadata_list[0].get_m())

