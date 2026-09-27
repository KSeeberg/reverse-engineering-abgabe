/* gordian - native RE-Challenge: der Check laeuft durch eine TIEFE, ver-
 * schachtelte Aufrufkette f0->f1->...->f7. Constraints (inkl. Produkte/ANDs,
 * nicht invertierbar) sind ueber die Funktionen verteilt und verschluesselt.
 * Man muss sich in Ghidra von Funktion zu Funktion hangeln.               */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "data.h"

static char sb[80];
static char *S(const unsigned char*e,int n){for(int i=0;i<n;i++)sb[i]=e[i]^0x5A;sb[n]=0;return sb;}
static uint64_t taint=0;
static void guard(void){ if(ptrace(PTRACE_TRACEME,0,(void*)1,0)<0) taint=0xFEEDFACEFEEDFACEULL; }
static unsigned rol8(unsigned x,int n){return((x<<n)|(x>>(8-n)))&0xFF;}
static unsigned mix(unsigned s,unsigned a,unsigned b){ s=(s+a)&0xFF; s=rol8(s,3); s^=b; return s&0xFF; }

/* verschluesselte Targets: KK(i) dekodiert zur Laufzeit (KEY volatil) */
static volatile unsigned char KEYSLOT[2]={DKEY,0};
#define KK(i) (unsigned char)(KENC[i]^KEY)

/* ===== tote Fake-Krypto (Rauschen) ===== */
static uint32_t fake_md5(const char*s){uint32_t a=0x67452301,b=0xefcdab89;for(;*s;s++){a=(a<<7|a>>25)^((unsigned char)*s*b);b+=0x9e3779b9;}return a^b;}
static int fake_rc4(const char*k){unsigned char x[256];for(int i=0;i<256;i++)x[i]=i;int j=0;for(int i=0;i<256;i++){j=(j+x[i]+k[i&7])&255;unsigned char t=x[i];x[i]=x[j];x[j]=t;}return x[0];}
static int op_true(int x){return((x|1)&1);}

/* ===== ECHTE Kette (tief verschachtelt) - definiert von innen nach aussen ===== */
__attribute__((noinline)) static int f7(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[14],p[15]);                       /* Paar 7 */
    int ok=1;
    if(((p[8]+3*p[9]+5*p[10]+7*p[11])&0xFF)!=KK(13)) ok=0;   /* L2 */
    if(((p[12]+3*p[13]+5*p[14]+7*p[15])&0xFF)!=KK(14)) ok=0; /* L3 */
    if(((rol8(p[7],5)^p[8])&0xFF)!=KK(16)) ok=0;             /* R1 */
    if((p[3]&p[11])!=KK(20)) ok=0;                            /* A3 */
    if((s&0xFF)!=KK(21)) ok=0;                                /* STATE (koppelt Kette) */
    return ok;
}
__attribute__((noinline)) static int f6(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[12],p[13]);                        /* Paar 6 */
    int ok=1;
    if(((p[0]+3*p[1]+5*p[2]+7*p[3])&0xFF)!=KK(11)) ok=0;     /* L0 */
    if(((p[4]+3*p[5]+5*p[6]+7*p[7])&0xFF)!=KK(12)) ok=0;     /* L1 */
    if(((rol8(p[0],3)+p[15])&0xFF)!=KK(15)) ok=0;            /* R0 */
    return ok && f7(p,s,KEY);
}
__attribute__((noinline)) static int f5(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[10],p[11]);                        /* Paar 5 */
    int ok=1;
    if(((p[12]*p[13])&0xFF)!=KK(9)) ok=0;        /* M6 */
    if(((p[14]*p[15])&0xFF)!=KK(10)) ok=0;       /* M7 */
    if((p[2]&p[10])!=KK(19)) ok=0;               /* A2 */
    return ok && f6(p,s,KEY);
}
/* f4 ist zusaetzlich CONTROL-FLOW-FLATTENED */
static volatile int VZ=0;
__attribute__((noinline)) static int f4(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[8],p[9]);                          /* Paar 4 */
    int ok=1; volatile int nx[4]; nx[2]=1; nx[1]=3; nx[3]=0; nx[0]=-1;
    int st=2;
    for(;;){ switch(st^(VZ&0)){
        case 2: if(((p[8]*p[9])&0xFF)!=KK(7)) ok=0; st=nx[2]; break;    /* M4 */
        case 1: if(((p[10]*p[11])&0xFF)!=KK(8)) ok=0; st=nx[1]; break;  /* M5 */
        case 3: st=nx[3]; break;                                        /* leer */
        default: return ok && f5(p,s,KEY);
    }}
}
__attribute__((noinline)) static int f3(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[6],p[7]);                          /* Paar 3 */
    int ok=1;
    if(((p[4]*p[5])&0xFF)!=KK(5)) ok=0;          /* M2 */
    if(((p[6]*p[7])&0xFF)!=KK(6)) ok=0;          /* M3 */
    if((p[1]&p[9])!=KK(18)) ok=0;                /* A1 */
    return ok && f4(p,s,KEY);
}
__attribute__((noinline)) static int f2(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[4],p[5]);                          /* Paar 2 */
    int ok=1;
    if(((p[0]*p[1])&0xFF)!=KK(3)) ok=0;          /* M0 */
    if(((p[2]*p[3])&0xFF)!=KK(4)) ok=0;          /* M1 */
    return ok && f3(p,s,KEY);
}
__attribute__((noinline)) static int f1(const unsigned char*p,unsigned s,unsigned KEY){
    s=mix(s,p[2],p[3]);                          /* Paar 1 */
    unsigned xe=0,xo=0;
    for(int i=0;i<16;i+=2)xe^=p[i];
    for(int i=1;i<16;i+=2)xo^=p[i];
    int ok=(xe==KK(1)&&xo==KK(2));               /* XE,XO */
    return ok && f2(p,s,KEY);
}
__attribute__((noinline)) static int f0(const unsigned char*p,unsigned KEY){
    unsigned s=mix(0x3C,p[0],p[1]);              /* Paar 0 */
    unsigned sum=0; for(int i=0;i<16;i++)sum+=p[i];
    int ok=((sum&0xFF)==KK(0)) && ((p[0]&p[8])==KK(17));   /* SUM,A0 */
    return ok && f1(p,s,KEY);
}

/* ===== DECOY-Kette (invertierbarer Transform -> ueberzeugender Fake-Flag) ===== */
__attribute__((noinline)) static int g_step(const char*sv,int i,unsigned acc){
    if(i==16) return 1;
    unsigned t=rol8((unsigned char)sv[i],RA[i]); t^=KA[i]; t=(t+acc)&0xFF;
    if((unsigned char)t!=TGA[i]) return 0;
    return g_step(sv,i+1,t);                      /* auch die Decoy-Kette ist verschachtelt */
}
static int check_decoy(const char*sv){ return g_step(sv,0,0x3C); }

static uint64_t fnv1a(const char*p){uint64_t h=0xcbf29ce484222325ULL;while(*p){h^=(unsigned char)*p++;h*=0x100000001b3ULL;}return h;}
static void emit(const unsigned char*ct,int n,const char*sv){
    uint64_t st=fnv1a(sv)^taint,A=0x2545F4914F6CDD1DULL,C=0x9E3779B97F4A7C15ULL;char out[80];
    for(int i=0;i<n;i++){st=st*A+C;out[i]=ct[i]^((st>>24)&0xFF);}out[n]=0;
    printf("%s\n",S(OBF_GR,sizeof OBF_GR)); printf("%s%s\n",S(OBF_FL,sizeof OBF_FL),out);
}


/* ===== Falscher Weg 2: affiner Per-Byte-Check (eigene rekursive Kette) ===== */
__attribute__((noinline)) static int aff_step(const char*sv,int i){
    if(i==16) return 1;
    if((((unsigned char)sv[i]*MA[i]+MB[i])&0xFF)!=TT[i]) return 0;
    return aff_step(sv,i+1);                     /* verschachtelt -> Sackgasse zum Durchhangeln */
}
static int check_affine(const char*sv){ return aff_step(sv,0); }

/* ===== Falscher Weg 3: Env-Backdoor LABY_KEY ===== */
__attribute__((noinline)) static int backdoor(char*out){
    const char*k=getenv("GORDIAN_KEY"); if(!k) return 0;
    int n=(int)sizeof(OBF_BACKKEY);
    for(int i=0;i<n;i++){ char c=OBF_BACKKEY[i]^0x5A; if(k[i]!=c) return 0; out[i]=c; }
    out[n]=0; return k[n]==0;
}

int main(int argc,char**argv){
    guard();
    volatile unsigned noise=fake_md5(argv[0])^fake_rc4("zzzzzzzz")^OBF_M0[0]^OBF_M1[0]^OBF_M2[0]^OBF_M3[0];(void)noise;
    if(argc!=2||strlen(argv[1])!=16){fprintf(stderr,"Usage: %s <serial(16)>\n",argv[0]);return 2;}
    const char*sv=argv[1];
    unsigned KEY=KEYSLOT[VZ];
    char bk[40];
    if(backdoor(bk)){ emit(FCT3,FCT3_LEN,bk); return 0; }        /* falscher Weg 3 */
    if(check_decoy(sv)){ emit(FCT,FCT_LEN,sv); return 0; }        /* falscher Weg 1 */
    if(check_affine(sv)){ emit(FCT2,FCT2_LEN,sv); return 0; }     /* falscher Weg 2 */
    if(op_true(argc) && f0((const unsigned char*)sv,KEY)){ emit(RCT,RCT_LEN,sv); return 0; }  /* ECHT */
    printf("%s\n",S(OBF_DN,sizeof OBF_DN));
    return 1;
}
