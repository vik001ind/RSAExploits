from sage.all_cmdline import *
from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import mod_inv
from RSAExploits import Franklin_Reiter
import sys

sys.setrecursionlimit(10000)

N = 0xfd2adfc8f9e88d3f31941e82bef75f6f9afcbba4ba2fc19e71aab2bf5eb3dbbfb1ff3e84b6a4900f472cc9450205d2062fa6e532530938ffb9e144e4f9307d8a2ebd01ae578fd10699475491218709cfa0aa1bfbd7f2ebc5151ce9c7e7256f14915a52d235625342c7d052de0521341e00db5748bcad592b82423c556f1c1051
e = 3
id1 =  37
id2 = 52
c1 = 0x81579ec88d73deaf602426946939f0339fed44be1b318305e1ab8d4d77a8e1dd7c67ea9cbac059ef06dd7bb91648314924d65165ec66065f4af96f7b4ce53f8edac10775e0d82660aa98ca62125699f7809dac8cf1fc8d44a09cc44f0d04ee318fb0015e5d7dcd7a23f6a5d3b1dbbdf8aab207245edf079d71c6ef5b3fc04416L
c2 = 0x1348effb7ff42372122f372020b9b22c8e053e048c72258ba7a2606c82129d1688ae6e0df7d4fb97b1009e7a3215aca9089a4dfd6e81351d81b3f4e1b358504f024892302cd72f51000f1664b2de9578fbb284427b04ef0a38135751864541515eada61b4c72e57382cf901922094b3fe0b5ebbdbac16dc572c392f6c9fbd01eL
b = -555
a = 37 * mod_inv(52, N)

info_dict = {}
rsadata_list = []
rsadata_list.append(RSAData(rsa_obj(long(N), long(e)), TextData(c1)))
rsadata_list.append(RSAData(rsa_obj(long(N), long(e)), TextData(c2)))

x = PolynomialRing(ZZ.quo(N*ZZ), 'x').gen()
poly = a*x + b
info_dict["Franklin_Reiter"] = poly

# Run specific exploit
if Franklin_Reiter().run(rsadata_list, info_dict):
    plaintext = rsadata_list[0].get_m()
    message = (plaintext * mod_inv(id2, N) - id2) % N
    print num2string(message)

# Run list of exploits
rsa_cracker.init()
if rsa_cracker.attack(rsadata_list, info_dict=info_dict):
    plaintext = rsadata_list[0].get_m()
    message = (plaintext * mod_inv(id2, N) - id2) % N
    print num2string(message)
