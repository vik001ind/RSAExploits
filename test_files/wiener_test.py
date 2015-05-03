from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import Wiener
import sys

sys.setrecursionlimit(10000)

# Parse and store all of the ciphertexts provided by the file
rsadata_list = []
c = None
e = None
N = None
f = open("wiener_list.txt", 'r')
for line in f:
    line = line.strip("{}").split(":")
    N = long(line[0], 0)
    e = long(line[1], 0)
    c = long(line[2].split("}")[0], 0)
    rsadata_list.append(RSAData(rsa_obj(N, e), TextData(c)))
f.close()

# Run the exploit by specifying it
if Wiener().run(rsadata_list):
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
