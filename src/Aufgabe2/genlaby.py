from z3 import *
import random
random.seed(0xBEEF)
MASK=(1<<64)-1; A=0x2545F4914F6CDD1D; C=0x9E3779B97F4A7C15
SERIAL="L4byr1nth-D3p#42"; assert len(SERIAL)==16
REAL_FLAG="DHBW{n3st3d_c4lls_z3_4nd_much_p4t13nc3}"
p=[ord(c) for c in SERIAL]
def rol(x,n): return ((x<<n)|(x>>(8-n)))&0xFF

# --- verteilte Constraints (nicht invertierbar wegen Produkten/AND) ---
def consts(p):
    K={}
    K["SUM"]=sum(p)&0xFF
    xe=0
    for i in range(0,16,2): xe^=p[i]
    K["XE"]=xe
    xo=0
    for i in range(1,16,2): xo^=p[i]
    K["XO"]=xo
    for j in range(8): K[f"M{j}"]=(p[2*j]*p[2*j+1])&0xFF          # Produkte -> nicht invertierbar
    for j in range(4): K[f"L{j}"]=(p[4*j]+3*p[4*j+1]+5*p[4*j+2]+7*p[4*j+3])&0xFF
    K["R0"]=(rol(p[0],3)+p[15])&0xFF
    K["R1"]=(rol(p[7],5)^p[8])&0xFF
    for j in range(4): K[f"A{j}"]=(p[j]&p[j+8])                    # AND -> nicht invertierbar
    return K
KB=consts(p)
# --- gekoppelter Kettenzustand (zwingt, alle Stufen zu lesen) ---
def statechain(p):
    s=0x3C
    for k in range(8):
        s=(s+p[2*k])&0xFF; s=rol(s,3); s^=p[2*k+1]; s&=0xFF
    return s
KSTATE=statechain(p)

# --- Eindeutigkeit beweisen ---
X=[BitVec(f"p{i}",8) for i in range(16)]
def build(s):
    s.add(Sum(X)&0xFF==KB["SUM"])
    xe=X[0]
    for i in range(2,16,2): xe=xe^X[i]
    s.add(xe==KB["XE"])
    xo=X[1]
    for i in range(3,16,2): xo=xo^X[i]
    s.add(xo==KB["XO"])
    for j in range(8): s.add((X[2*j]*X[2*j+1])&0xFF==KB[f"M{j}"])
    for j in range(4): s.add((X[4*j]+3*X[4*j+1]+5*X[4*j+2]+7*X[4*j+3])&0xFF==KB[f"L{j}"])
    s.add(((((X[0]<<3)|LShR(X[0],5))&0xFF)+X[15])&0xFF==KB["R0"])
    s.add(((((X[7]<<5)|LShR(X[7],3))&0xFF)^X[8])&0xFF==KB["R1"])
    for j in range(4): s.add((X[j]&X[j+8])==KB[f"A{j}"])
    st=BitVecVal(0x3C,8)
    for k in range(8):
        st=(st+X[2*k])&0xFF; st=(((st<<3)|LShR(st,5))&0xFF); st=st^X[2*k+1]
    s.add(st==KSTATE)
    for x in X: s.add(x>=0x20,x<=0x7e)
s=Solver(); build(s); assert s.check()==sat
m=s.model(); sol=bytes(m[X[i]].as_long() for i in range(16))
s.add(Or([X[i]!=sol[i] for i in range(16)])); uniq=s.check()==unsat
print("[gen] z3-Loesung:",sol.decode(),"| eindeutig:",uniq); assert sol.decode()==SERIAL and uniq

# --- Decoy-Kette (invertierbarer Transform -> ueberzeugender Fake) ---
DECOY_SERIAL="0v3rr1d3-r00t!!!"; assert len(DECOY_SERIAL)==16
FAKE_FLAG="root-override: kein Flag auf diesem Pfad"
RA=[(i*5+3)%7+1 for i in range(16)]; KA=[random.randrange(256) for _ in range(16)]
def transA(s):
    acc=0x3C;o=[]
    for i,ch in enumerate(s.encode()): t=rol(ch,RA[i]);t^=KA[i];t=(t+acc)&0xFF;acc=t;o.append(t)
    return o
TGA=transA(DECOY_SERIAL)

def fnv1a(b):
    h=0xcbf29ce484222325
    for x in b: h^=x; h=(h*0x100000001b3)&MASK
    return h
def ks(seed,n):
    st=seed
    for _ in range(n): st=(st*A+C)&MASK; yield (st>>24)&0xFF
RCT=[b^k for b,k in zip(REAL_FLAG.encode(),ks(fnv1a(SERIAL.encode()),len(REAL_FLAG)))]
FCT=[b^k for b,k in zip(FAKE_FLAG.encode(),ks(fnv1a(DECOY_SERIAL.encode()),len(FAKE_FLAG)))]

KEY=0x6D
order=["SUM","XE","XO"]+[f"M{j}" for j in range(8)]+[f"L{j}" for j in range(4)]+["R0","R1"]+[f"A{j}" for j in range(4)]+["STATE"]
vals=[KB[k] for k in order[:-1]]+[KSTATE]
def ob(s): return [c^0x5A for c in s.encode()]
def arr(n,xs): return f"static const unsigned char {n}[]={{"+",".join('0x%02x'%x for x in xs)+"};"
with open("data.h","w") as f:
    f.write("// verschluesselte Constraint-Targets (XOR 0x%02x, Laufzeit-Decode)\n"%KEY)
    f.write(arr("KENC",[v^KEY for v in vals])+"\n")
    f.write(arr("RA",RA)+"\n"+arr("KA",KA)+"\n"+arr("TGA",TGA)+"\n")
    f.write(f"static const int RCT_LEN={len(RCT)};\n"+arr("RCT",RCT)+"\n")
    f.write(f"static const int FCT_LEN={len(FCT)};\n"+arr("FCT",FCT)+"\n")
    f.write(arr("OBF_GR",ob("Access granted."))+"\n"+arr("OBF_FL",ob("Flag: "))+"\n"+arr("OBF_DN",ob("Access denied."))+"\n")
    for i,fk in enumerate(["DHBW{d3bug_bu1ld_1ntern4l}","DHBW{qa_sm0k3_t3st_0k}","DHBW{l3g4cy_k3y_d0_n0t_us3}"]):
        f.write(arr(f"OBF_N{i}",ob(fk))+"\n")
    f.write("#define DKEY 0x%02x\n"%KEY)
    # index map for solver reference
print("[gen] REAL:",SERIAL,"-> ",REAL_FLAG)
print("[gen] DECOY:",DECOY_SERIAL,"-> ",FAKE_FLAG)
print("[gen] KSTATE=0x%02x"%KSTATE)
print("checks:",bytes(c^k for c,k in zip(RCT,ks(fnv1a(SERIAL.encode()),len(RCT)))).decode(),"|",
      bytes(c^k for c,k in zip(FCT,ks(fnv1a(DECOY_SERIAL.encode()),len(FCT)))).decode())

# ================= ZUSAETZLICHE FALSCHE WEGE =================
import random as _r
_r.seed(0xDEAD)
def _fnv(b):
    h=0xcbf29ce484222325
    for x in b: h^=x; h=(h*0x100000001b3)&MASK
    return h
def _ks(seed,n):
    st=seed
    for _ in range(n): st=(st*A+C)&MASK; yield (st>>24)&0xFF

# Falscher Weg 2: affiner Per-Byte-Check (mit Python invertierbar -> Falle)
D2="S3rv1c3-M0d3-K3y"; assert len(D2)==16
FAKE2="TOKEN=service-mode lvl=2 (kein Flag)"
MA=[_r.randrange(1,256)|1 for _ in range(16)]   # ungerade -> invertierbar mod 256
MB=[_r.randrange(256) for _ in range(16)]
TT=[((ord(D2[i])*MA[i]+MB[i])&0xFF) for i in range(16)]
# sicherstellen, dass das ECHTE Serial diesen Decoy NICHT erfuellt:
assert any(((p[i]*MA[i]+MB[i])&0xFF)!=TT[i] for i in range(16))
FCT2=[b^k for b,k in zip(FAKE2.encode(),_ks(_fnv(D2.encode()),len(FAKE2)))]

# Falscher Weg 3: Env-Backdoor (LABY_KEY)
BACKKEY="DHBW-DEV-ACCESS-2024"
FAKE3="debug backdoor offen - hier ist nichts"
FCT3=[b^k for b,k in zip(FAKE3.encode(),_ks(_fnv(BACKKEY.encode()),len(FAKE3)))]

def _ob(s): return [c^0x5A for c in s.encode()]
def _arr(n,xs): return f"static const unsigned char {n}[]={{"+",".join('0x%02x'%x for x in xs)+"};"
with open("data.h","a") as f:
    f.write("\n// --- zusaetzliche falsche Wege ---\n")
    f.write(_arr("MA",MA)+"\n"+_arr("MB",MB)+"\n"+_arr("TT",TT)+"\n")
    f.write(f"static const int FCT2_LEN={len(FCT2)};\n"+_arr("FCT2",FCT2)+"\n")
    f.write(_arr("OBF_BACKKEY",_ob(BACKKEY))+"\n")
    f.write(f"static const int FCT3_LEN={len(FCT3)};\n"+_arr("FCT3",FCT3)+"\n")
    for i,fk in enumerate(["DHBW{pr3_r3l34s3_t0k3n}","DHBW{c1_p1p3l1n3_s3cr3t}","DHBW{f4ll1ng_f0r_1t_huh}","DHBW{4lm0st_th3r3_n0p3}"]):
        f.write(_arr(f"OBF_M{i}",_ob(fk))+"\n")
print("[gen+] Decoy2(affin):",D2,"->",FAKE2)
print("[gen+] Backdoor LABY_KEY=",BACKKEY,"->",FAKE3)
