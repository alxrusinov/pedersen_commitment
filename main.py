# pip install tinyec

from tinyec.ec import SubGroup, Curve, Point
import secrets

name = 'secp256k1'

'''
Config example
config = {
    'p': 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    'n': 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    'a': 0x0000000000000000000000000000000000000000000000000000000000000000,
    'b': 0x0000000000000000000000000000000000000000000000000000000000000007,
    'g': (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    'h': 1
}
'''

def get_field(p,g,n,h):
  return SubGroup(p,g,n, h)

def get_curve(a,b,field,name=name):
  return Curve(a,b,field,name)

def get_private_key(curve):
  return secrets.randbelow(curve.field.n)

def get_public_key(pk, curve):
  return pk*curve.g

# config_G, config_H - словари, содержащие значения для генерации эллиптических кривых G и H
# v - знасение входа или выхода транзакции
# на выходе r*G + v*H
def get_pedersen(config_G, config_H, v):
  field_G = get_field(config_G['p'], config_G['g'], config_G['n'], config_G['h'])
  G = get_curve(config_G['a'], config_G['b'], field_G)
  pk_G = get_private_key(G)
  pc_G = get_public_key(pk_G, G)

  field_H = get_field(config_H['p'], config_H['g'], config_H['n'], config_H['h'])
  H = get_curve(config_H['a'], config_H['b'], field_H)
  pk_H = get_public_key(v,H)

  return pk_G + pk_H

