from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import Common_Factor
import sys

sys.setrecursionlimit(10000)

# Parse and store all of the ciphertexts provided by the file
rsadata_list = []
c = None
e = None
N = None
f = open("common_factor_test.txt", 'r')
for line in f:
	if line.startswith("ciphertext"):
		c = long(line.split(" ")[2], 0)
	elif line.startswith("e"):
		e = long(line.split(" ")[2])
	elif line.startswith("N"):
		N = long(line.split(" ")[2], 0)
		rsadata_list.append(RSAData(rsa_obj(N, e), TextData(c)))
f.close()

# Run the exploit by specifying it
if Common_Factor().run(rsadata_list):
    for rsadata in rsadata_list:
        if rsadata.get_d() != None and rsadata.get_c() != 0:
            rsadata.decrypt()
            print num2string(rsadata.get_m())

print "----------------------------------------------------"

# Run list of exploits
rsa_cracker.init()
if rsa_cracker.attack(rsadata_list):
    for rsadata in rsadata_list:
        if rsadata.get_d() != None and rsadata.get_c() != 0:
            rsadata.decrypt()
            print num2string(rsadata.get_m())
