from z3 import *
import random
random.seed(0x9A17)
MASK=(1<<64)-1; A=0x2545F4914F6CDD1D; C=0x9E3779B97F4A7C15
SERIAL="Kn0t-Cutt3r#2026"; assert len(SERIAL)==16
REAL_FLAG="DHBW{0nly_th1s_p4th_c4rr13s_th3_s1gn4tur3}"     # nur DER echte Weg -> DHBW
p=[ord(c) for c in SERIAL]
def rol(x,n): return ((x<<n)|(x>>(8-n)))&0xFF
def consts(p):
    K={}; K["SUM"]=sum(p)&0xFF
    xe=0
    for i in range(0,16,2): xe^=p[i]
    K["XE"]=xe
    xo=0
    for i in range(1,16,2): xo^=p[i]
    K["XO"]=xo
    for j in range(8): K[f"M{j}"]=(p[2*j]*p[2*j+1])&0xFF
    for j in range(4): K[f"L{j}"]=(p[4*j]+3*p[4*j+1]+5*p[4*j+2]+7*p[4*j+3])&0xFF
    K["R0"]=(rol(p[0],3)+p[15])&0xFF; K["R1"]=(rol(p[7],5)^p[8])&0xFF
    for j in range(4): K[f"A{j}"]=(p[j]&p[j+8])
    return K
KB=consts(p)
def statechain(p):
    s=0x3C
    for k in range(8): s=(s+p[2*k])&0xFF; s=rol(s,3); s^=p[2*k+1]; s&=0xFF
    return s
KSTATE=statechain(p)
X=[BitVec(f"p{i}",8) for i in range(16)]
s=Solver()
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
assert s.check()==sat
m=s.model(); sol=bytes(m[X[i]].as_long() for i in range(16))
s.add(Or([X[i]!=sol[i] for i in range(16)])); uniq=s.check()==unsat
print("[gen] z3:",sol.decode(),"eindeutig:",uniq); assert sol.decode()==SERIAL and uniq

def fnv(b):
    h=0xcbf29ce484222325
    for x in b: h^=x; h=(h*0x100000001b3)&MASK
    return h
def ks(seed,n):
    st=seed
    for _ in range(n): st=(st*A+C)&MASK; yield (st>>24)&0xFF
def enc(text,keyserial): return [b^k for b,k in zip(text.encode(),ks(fnv(keyserial.encode()),len(text)))]

RCT=enc(REAL_FLAG,SERIAL)

# ---- Falsche Wege: Ausgaben OHNE DHBW-Praefix ----
D1="0v3rr1d3-r00t!!!"; OUT1="svc-mode: ok (kein Flag auf diesem Pfad)"
D2="S3rv1c3-M0d3-K3y"; OUT2="TOKEN=7f3a9c21 access=service level=2"
BACKKEY="GORDIAN-DEV-ACCESS-2026"; OUT3="debug console bereit - hier ist nichts"
RA=[(i*5+3)%7+1 for i in range(16)]; KA=[random.randrange(256) for _ in range(16)]
def transA(sr):
    acc=0x3C;o=[]
    for i,ch in enumerate(sr.encode()): t=rol(ch,RA[i]);t^=KA[i];t=(t+acc)&0xFF;acc=t;o.append(t)
    return o
TGA=transA(D1)
MA=[random.randrange(1,256)|1 for _ in range(16)]; MB=[random.randrange(256) for _ in range(16)]
TT=[((ord(D2[i])*MA[i]+MB[i])&0xFF) for i in range(16)]
assert any(((p[i]*MA[i]+MB[i])&0xFF)!=TT[i] for i in range(16))   # echtes Serial faellt durch Decoy2
FCT =enc(OUT1,D1); FCT2=enc(OUT2,D2); FCT3=enc(OUT3,BACKKEY)

KEY=0x6D
order=["SUM","XE","XO"]+[f"M{j}" for j in range(8)]+[f"L{j}" for j in range(4)]+["R0","R1"]+[f"A{j}" for j in range(4)]
vals=[KB[k] for k in order]+[KSTATE]
def ob(sx): return [c^0x5A for c in sx.encode()]
def arr(n,xs): return f"static const unsigned char {n}[]={{"+",".join('0x%02x'%x for x in xs)+"};"
with open("data.h","w") as f:
    f.write(arr("KENC",[v^KEY for v in vals])+"\n#define DKEY 0x%02x\n"%KEY)
    f.write(arr("RA",RA)+"\n"+arr("KA",KA)+"\n"+arr("TGA",TGA)+"\n"+arr("MA",MA)+"\n"+arr("MB",MB)+"\n"+arr("TT",TT)+"\n")
    f.write(f"static const int RCT_LEN={len(RCT)};\n"+arr("RCT",RCT)+"\n")
    f.write(f"static const int FCT_LEN={len(FCT)};\n"+arr("FCT",FCT)+"\n")
    f.write(f"static const int FCT2_LEN={len(FCT2)};\n"+arr("FCT2",FCT2)+"\n")
    f.write(f"static const int FCT3_LEN={len(FCT3)};\n"+arr("FCT3",FCT3)+"\n")
    f.write(arr("OBF_GR",ob("Zugriff ok."))+"\n"+arr("OBF_FL",ob("Ausgabe: "))+"\n"+arr("OBF_DN",ob("Zugriff verweigert."))+"\n")
    f.write(arr("OBF_BACKKEY",ob(BACKKEY))+"\n")
    for i,fk in enumerate(["SVC{internal_build}","ROOT-2026-XY","key=0xdeadbeef","try-harder-123"]):
        f.write(arr(f"OBF_M{i}",ob(fk))+"\n")
print("[gen] REAL :",SERIAL,"->",REAL_FLAG)
print("[gen] Weg1 :",D1,"->",OUT1)
print("[gen] Weg2 :",D2,"->",OUT2)
print("[gen] Weg3 : LABY? env GORDIAN_KEY=",BACKKEY,"->",OUT3)
