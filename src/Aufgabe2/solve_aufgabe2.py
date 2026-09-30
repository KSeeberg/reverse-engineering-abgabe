#!/usr/bin/env python3
# Loeser fuer aufgabe2. Ein einfaches Invert geht NICHT (Produkte & ANDs sind
# nicht umkehrbar) -> die ueber f0..f7 verteilten Constraints werden aus Ghidra
# extrahiert und als SMT-Problem mit z3 geloest. Targets sind verschluesselt
# (KENC XOR DKEY) und muessen erst dekodiert werden.
from z3 import *
import re
MASK=(1<<64)-1; A=0x2545F4914F6CDD1D; C=0x9E3779B97F4A7C15
d=open("data.h").read()
DKEY=int(re.search(r"#define DKEY (0x[0-9a-f]+)",d).group(1),16)
def arr(n): return [int(x,16) for x in re.search(rf"{n}\[\]=\{{([^}}]*)\}}",d).group(1).split(",")]
KENC=arr("KENC"); RCT=arr("RCT")
K=[e^DKEY for e in KENC]          # dekodierte Targets
# Index-Map: 0 SUM,1 XE,2 XO,3..10 M0..M7,11..14 L0..L3,15 R0,16 R1,17..20 A0..A3,21 STATE
X=[BitVec(f"p{i}",8) for i in range(16)]
s=Solver()
s.add(Sum(X)&0xFF==K[0])
xe=X[0]
for i in range(2,16,2): xe=xe^X[i]
s.add(xe==K[1])
xo=X[1]
for i in range(3,16,2): xo=xo^X[i]
s.add(xo==K[2])
for j in range(8): s.add((X[2*j]*X[2*j+1])&0xFF==K[3+j])
for j in range(4): s.add((X[4*j]+3*X[4*j+1]+5*X[4*j+2]+7*X[4*j+3])&0xFF==K[11+j])
s.add(((((X[0]<<3)|LShR(X[0],5))&0xFF)+X[15])&0xFF==K[15])
s.add(((((X[7]<<5)|LShR(X[7],3))&0xFF)^X[8])&0xFF==K[16])
for j in range(4): s.add((X[j]&X[j+8])==K[17+j])
st=BitVecVal(0x3C,8)
for k in range(8):
    st=(st+X[2*k])&0xFF; st=(((st<<3)|LShR(st,5))&0xFF); st=st^X[2*k+1]
s.add(st==K[21])
for x in X: s.add(x>=0x20,x<=0x7e)
assert s.check()==sat
pw=bytes(s.model()[X[i]].as_long() for i in range(16))
def fnv1a(b):
    h=0xcbf29ce484222325
    for x in b: h^=x; h=(h*0x100000001b3)&MASK
    return h
def ks(seed,n):
    stt=seed
    for _ in range(n): stt=(stt*A+C)&MASK; yield (stt>>24)&0xFF
flag=bytes(c^k for c,k in zip(RCT,ks(fnv1a(pw),len(RCT))))
print("[+] Serial:",pw.decode()); print("[+] Flag  :",flag.decode())
