/*
 * Ed448-Goldilocks + AuthPAK primitives for dp9ik authentication.
 * Ported from 9front/drawterm authpak.c (.mpc files) using OpenSSL BIGNUM.
 *
 * Curve: x^2 + y^2 = 1 + d*x^2*y^2  (Goldilocks form, a=1)
 *   d = -39081 mod p
 *   p = 2^448 - 2^224 - 1
 *   Base point: G_y = 19, G_x = 297EA0EA...
 *
 * Points encoded using Decaf (56 bytes, not standard 57-byte Ed448).
 * All arithmetic matches 9front libauthsrv/authpak.c exactly.
 */

#include "ed448.h"
#include "devfactotum.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

/* ------------------------------------------------------------------ */
/*  Global curve parameters                                             */
/* ------------------------------------------------------------------ */

static BIGNUM *G_P;       /* Field prime p = 2^448 - 2^224 - 1 */
static BIGNUM *G_A;       /* Curve a = 1 */
static BIGNUM *G_D;       /* Curve d = -39081 mod p */
static BIGNUM *G_GX;      /* Base point x */
static BIGNUM *G_GY;      /* Base point y = 19 */
static BIGNUM *G_N;       /* Group order */
static BIGNUM *G_NONSQR;  /* Smallest non-square element mod p (for elligator2) */
static BIGNUM *G_SQRT_EXP; /* (p+1)/4 for square root */
static BIGNUM *G_ISQRT_EXP; /* (p-3)/4 for misqrt */
static BN_CTX *G_CTX;
static int G_initialized = 0;

/* p = 2^448 - 2^224 - 1 (exactly 112 hex chars = 56 bytes) */
#define P448_HEX \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

/* d = p - 39081 (exactly 112 hex chars = 56 bytes) */
#define D448_HEX \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756"

/* Group order n = 2^446 - 13818066... */
#define N448_HEX \
    "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"

/*
 * Base point from 9front ed448.mpc:
 *   G_x = 297EA0EA2692FF1B4FAFF46098453A6A26ADF733245F065C3C59D0709CECFA96147EAAF3932D94C63D96C170033F4BA0C7F0DE840AED939F
 *   G_y = 19
 */
#define GX_HEX \
    "297EA0EA2692FF1B4FAFF46098453A6A26ADF733245F065C3C59D0709CECFA96147EAAF3932D94C63D96C170033F4BA0C7F0DE840AED939F"

/* ------------------------------------------------------------------ */
/*  Extended point (X:Y:Z:T)                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;
    BIGNUM *T;  /* T = X*Y/Z (twist coordinate) */
} Pt448;

static Pt448 *pt_new(void)
{
    Pt448 *p = (Pt448 *)malloc(sizeof(Pt448));
    if (!p) return NULL;
    p->X = BN_new(); p->Y = BN_new(); p->Z = BN_new(); p->T = BN_new();
    if (!p->X || !p->Y || !p->Z || !p->T) {
        BN_free(p->X); BN_free(p->Y); BN_free(p->Z); BN_free(p->T);
        free(p); return NULL;
    }
    BN_zero(p->X); BN_one(p->Y); BN_one(p->Z); BN_zero(p->T);
    return p;
}

static void pt_free(Pt448 *p)
{
    if (!p) return;
    BN_free(p->X); BN_free(p->Y); BN_free(p->Z); BN_free(p->T);
    free(p);
}

static int pt_copy(Pt448 *dst, const Pt448 *src)
{
    if (!BN_copy(dst->X, src->X)) return -1;
    if (!BN_copy(dst->Y, src->Y)) return -1;
    if (!BN_copy(dst->Z, src->Z)) return -1;
    if (!BN_copy(dst->T, src->T)) return -1;
    return 0;
}

#define FE_ADD(r,a,b)  BN_mod_add((r),(a),(b),G_P,G_CTX)
#define FE_SUB(r,a,b)  BN_mod_sub((r),(a),(b),G_P,G_CTX)
#define FE_MUL(r,a,b)  BN_mod_mul((r),(a),(b),G_P,G_CTX)
#define FE_SQR(r,a)    BN_mod_sqr((r),(a),G_P,G_CTX)

/*
 * Extended point addition for twisted Edwards a=1:
 *   k1 = A = X1*X2,  k2 = B = Y1*Y2
 *   k3 = C = T1*d*T2,  k4 = D = Z1*Z2
 *   E = (X1+Y1)*(X2+Y2)-A-B
 *   F = D-C,  G = D+C,  H = B-A
 *   X3=E*F, Y3=G*H, Z3=F*G, T3=E*H
 */
static int pt_add(Pt448 *R, const Pt448 *P, const Pt448 *Q)
{
    BIGNUM *A, *B, *C, *D, *E, *F, *Gv, *H, *tmp;
    int ok = 0;

    A=BN_new(); B=BN_new(); C=BN_new(); D=BN_new();
    E=BN_new(); F=BN_new(); Gv=BN_new(); H=BN_new(); tmp=BN_new();
    if (!A||!B||!C||!D||!E||!F||!Gv||!H||!tmp) goto done;

    if (!FE_MUL(A, P->X, Q->X)) goto done;
    if (!FE_MUL(B, P->Y, Q->Y)) goto done;
    if (!FE_MUL(C, P->T, G_D)) goto done;
    if (!FE_MUL(C, C, Q->T)) goto done;
    if (!FE_MUL(D, P->Z, Q->Z)) goto done;
    if (!FE_ADD(tmp, P->X, P->Y)) goto done;
    if (!FE_ADD(E, Q->X, Q->Y)) goto done;
    if (!FE_MUL(E, tmp, E)) goto done;
    if (!FE_SUB(E, E, A)) goto done;
    if (!FE_SUB(E, E, B)) goto done;
    if (!FE_SUB(F, D, C)) goto done;
    if (!FE_ADD(Gv, D, C)) goto done;
    if (!FE_SUB(H, B, A)) goto done;
    if (!FE_MUL(R->X, E, F)) goto done;
    if (!FE_MUL(R->Y, Gv, H)) goto done;
    if (!FE_MUL(R->Z, F, Gv)) goto done;
    if (!FE_MUL(R->T, E, H)) goto done;
    ok = 1;

done:
    BN_free(A); BN_free(B); BN_free(C); BN_free(D);
    BN_free(E); BN_free(F); BN_free(Gv); BN_free(H); BN_free(tmp);
    return ok ? 0 : -1;
}

/*
 * Scalar multiplication: R = scalar * P (double-and-add).
 * scalar is a BN integer.
 */
static int pt_scalarmul(Pt448 *R, const BIGNUM *scalar, const Pt448 *P)
{
    Pt448 *accum, *addend, *tmp;
    int bits, i;

    accum = pt_new(); addend = pt_new(); tmp = pt_new();
    if (!accum || !addend || !tmp) {
        pt_free(accum); pt_free(addend); pt_free(tmp); return -1;
    }
    if (pt_copy(addend, P) < 0) goto err;
    bits = BN_num_bits(scalar);
    for (i = bits-1; i >= 0; i--) {
        if (pt_add(tmp, accum, accum) < 0) goto err;
        if (pt_copy(accum, tmp) < 0) goto err;
        if (BN_is_bit_set(scalar, i)) {
            if (pt_add(tmp, accum, addend) < 0) goto err;
            if (pt_copy(accum, tmp) < 0) goto err;
        }
    }
    if (pt_copy(R, accum) < 0) goto err;
    pt_free(accum); pt_free(addend); pt_free(tmp);
    return 0;
err:
    pt_free(accum); pt_free(addend); pt_free(tmp);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Field helpers                                                       */
/* ------------------------------------------------------------------ */

/*
 * Compute Legendre symbol (a/p): 1 if QR, -1 if non-QR, 0 if a=0.
 * Uses: (a/p) = a^((p-1)/2) mod p
 */
static int bn_legendre(const BIGNUM *a, BN_CTX *ctx)
{
    BIGNUM *exp, *r;
    int ret = 0;

    exp = BN_new(); r = BN_new();
    if (!exp || !r) { BN_free(exp); BN_free(r); return 0; }

    /* exp = (p-1)/2 */
    BN_copy(exp, G_P);
    BN_sub_word(exp, 1);
    BN_rshift1(exp, exp);

    BN_mod_exp(r, a, exp, G_P, ctx);

    if (BN_is_one(r)) {
        ret = 1;
    } else if (BN_cmp(r, G_P) < 0 && !BN_is_zero(r)) {
        /* check if r == p-1 */
        BIGNUM *pm1 = BN_new();
        BN_copy(pm1, G_P);
        BN_sub_word(pm1, 1);
        if (BN_cmp(r, pm1) == 0) ret = -1;
        BN_free(pm1);
    }
    BN_free(exp); BN_free(r);
    return ret;
}

/*
 * msqrt: compute square root of a mod p.
 * For p ≡ 3 (mod 4): sqrt(a) = a^((p+1)/4)
 * Returns 1 and sets r if a is QR, returns 0 and sets r=0 if not QR.
 */
static int bn_msqrt(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    BIGNUM *tmp;

    if (bn_legendre(a, ctx) != 1) {
        BN_zero(r);
        return 0;
    }
    /* r = a^((p+1)/4) */
    BN_mod_exp(r, a, G_SQRT_EXP, G_P, ctx);
    /* verify */
    tmp = BN_new();
    BN_mod_sqr(tmp, r, G_P, ctx);
    if (BN_cmp(tmp, a) != 0) { BN_zero(r); BN_free(tmp); return 0; }
    BN_free(tmp);
    return 1;
}

/*
 * misqrt: compute a^((p-3)/4) mod p.
 * For p ≡ 3 (mod 4): misqrt(a) = a^((p-3)/4) = 1/sqrt(a) when a is QR.
 */
static void bn_misqrt(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    /* r = a^((p-3)/4) */
    BN_mod_exp(r, a, G_ISQRT_EXP, G_P, ctx);
}

/* ------------------------------------------------------------------ */
/*  Decaf encoding/decoding                                             */
/* ------------------------------------------------------------------ */

/*
 * decaf_neg: if n > (p-1)/2, negate r (r = p - r).
 * Ported from 9front decaf.mpc:decaf_neg.
 */
static void decaf_neg_if(BIGNUM *r, const BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *half, *neg;
    half = BN_new(); neg = BN_new();
    BN_copy(half, G_P);
    BN_sub_word(half, 1);
    BN_rshift1(half, half);   /* half = (p-1)/2 */
    if (BN_cmp(n, half) > 0) {
        BN_mod_sub(neg, BN_value_one(), BN_value_one(), G_P, ctx); /* = 0 */
        BN_mod_sub(neg, neg, r, G_P, ctx);  /* neg = -r mod p = p-r */
        BN_copy(r, neg);
    }
    BN_free(half); BN_free(neg);
}

/*
 * decaf_encode: encode extended point (X:Y:Z:T) to 56-byte Decaf scalar s.
 * Ported from 9front decaf.mpc:decaf_encode.
 * Output: s[AUTH_PAKSLEN] in BIG-ENDIAN.
 */
static int decaf_encode_pt(unsigned char s[AUTH_PAKSLEN], const Pt448 *P)
{
    BIGNUM *u, *r, *s_bn, *tmp1, *tmp2, *tmp3, *tmp4, *tmp5;
    int ok = 0;

    u=BN_new(); r=BN_new(); s_bn=BN_new();
    tmp1=BN_new(); tmp2=BN_new(); tmp3=BN_new(); tmp4=BN_new(); tmp5=BN_new();
    if (!u||!r||!s_bn||!tmp1||!tmp2||!tmp3||!tmp4||!tmp5) goto done;

    /* tmp3 = a - d = 1 - (-39081) = 39082 */
    FE_SUB(tmp3, G_A, G_D);

    /* tmp1 = (a-d) * (Z+Y) * (Z-Y) */
    FE_ADD(tmp4, P->Z, P->Y);
    FE_MUL(tmp2, tmp3, tmp4);
    FE_SUB(tmp4, P->Z, P->Y);
    FE_MUL(tmp1, tmp2, tmp4);

    /* r = misqrt(tmp1) */
    bn_misqrt(r, tmp1, G_CTX);

    /* u = (a-d) * r */
    FE_MUL(u, tmp3, r);

    /* Determine sign: negate r if (-2*u*Z) > (p-1)/2 */
    FE_ADD(tmp1, u, u);      /* tmp1 = 2*u */
    FE_MUL(tmp1, tmp1, P->Z); /* tmp1 = 2*u*Z */
    FE_SUB(tmp1, BN_value_one(), tmp1); /* tmp1 = 1 - 2*u*Z (placeholder for -2*u*Z) */
    /* Actually we want -2*u*Z = p - 2*u*Z */
    BN_mod_sub(tmp1, BN_value_one(), tmp1, G_P, G_CTX); /* undo the +1 */
    /* Correct computation: -2*u*Z */
    FE_ADD(tmp4, u, u);
    FE_MUL(tmp4, tmp4, P->Z);
    BN_mod_sub(tmp1, BN_value_one(), tmp1, G_P, G_CTX);
    /* Restart: compute -2uZ cleanly */
    {
        BIGNUM *twouZ = BN_new();
        FE_ADD(twouZ, u, u);
        FE_MUL(twouZ, twouZ, P->Z);
        BN_mod_sub(tmp1, G_P, twouZ, G_P, G_CTX); /* tmp1 = -2uZ mod p */
        BN_free(twouZ);
    }
    decaf_neg_if(r, tmp1, G_CTX);

    /* s = u * (r*(a*Z*X - d*Y*T) + Y) / a  (a=1 so /a = identity) */
    /* aZX = a*Z*X = Z*X */
    FE_MUL(tmp2, G_A, P->Z);
    FE_MUL(tmp2, tmp2, P->X);  /* tmp2 = a*Z*X */
    /* dYT = d*Y*T */
    FE_MUL(tmp5, G_D, P->Y);
    FE_MUL(tmp5, tmp5, P->T);  /* tmp5 = d*Y*T */
    FE_SUB(tmp2, tmp2, tmp5);  /* tmp2 = a*Z*X - d*Y*T */
    FE_MUL(tmp4, r, tmp2);     /* tmp4 = r*(a*Z*X - d*Y*T) */
    FE_ADD(tmp4, tmp4, P->Y);  /* tmp4 = r*(a*Z*X - d*Y*T) + Y */
    FE_MUL(tmp1, u, tmp4);     /* tmp1 = u * (...) */
    /* /a: for a=1, invert(a)=1, no-op */
    BN_mod_inverse(tmp2, G_A, G_P, G_CTX);  /* should be 1 */
    FE_MUL(s_bn, tmp1, tmp2);

    /* Apply final decaf_neg: if s_bn > (p-1)/2, negate */
    decaf_neg_if(s_bn, s_bn, G_CTX);

    /* Encode s_bn as 56-byte big-endian */
    memset(s, 0, AUTH_PAKSLEN);
    {
        int nbytes = BN_num_bytes(s_bn);
        if (nbytes > AUTH_PAKSLEN) goto done;
        BN_bn2bin(s_bn, s + (AUTH_PAKSLEN - nbytes));
    }
    ok = 1;

done:
    BN_free(u); BN_free(r); BN_free(s_bn);
    BN_free(tmp1); BN_free(tmp2); BN_free(tmp3); BN_free(tmp4); BN_free(tmp5);
    return ok ? 0 : -1;
}

/*
 * decaf_decode: decode 56-byte big-endian Decaf scalar s to extended point.
 * Ported from 9front decaf.mpc:decaf_decode.
 * Returns 0 on success, -1 on failure (point not on curve).
 */
static int decaf_decode_pt(Pt448 *P, const unsigned char s[AUTH_PAKSLEN])
{
    BIGNUM *s_bn, *ss, *u, *v, *w, *Z, *ok, *tmp1, *tmp2, *tmp3, *tmp4, *tmp5, *tmp6;
    BIGNUM *half;
    int ret = -1;

    s_bn=BN_new(); ss=BN_new(); u=BN_new(); v=BN_new(); w=BN_new();
    Z=BN_new(); ok=BN_new();
    tmp1=BN_new(); tmp2=BN_new(); tmp3=BN_new(); tmp4=BN_new();
    tmp5=BN_new(); tmp6=BN_new(); half=BN_new();
    if (!s_bn||!ss||!u||!v||!w||!Z||!ok||!tmp1||!tmp2||!tmp3||!tmp4||!tmp5||!tmp6||!half)
        goto done;

    /* Decode s from 56-byte big-endian */
    BN_bin2bn(s, AUTH_PAKSLEN, s_bn);

    /* Check: s must be in [0, (p-1)/2] */
    BN_copy(half, G_P);
    BN_sub_word(half, 1);
    BN_rshift1(half, half);
    if (BN_cmp(s_bn, half) > 0) {
        /* s > (p-1)/2: invalid */
        goto done;
    }

    /* ss = s^2 */
    FE_SQR(ss, s_bn);

    /* Z = a*ss + 1  (a=1) */
    FE_MUL(Z, G_A, ss);
    FE_ADD(Z, Z, BN_value_one());

    /* u = Z^2 */
    FE_SQR(u, Z);

    /* u = u - 4*d*ss */
    BN_set_word(tmp4, 4);
    FE_MUL(tmp3, tmp4, G_D);
    FE_MUL(tmp2, tmp3, ss);
    FE_SUB(u, u, tmp2);

    /* v = u * ss */
    FE_MUL(v, u, ss);

    if (BN_is_zero(v)) {
        /* v=0: degenerate case, point is identity */
        BN_one(ok);
    } else {
        /* ok = sqrt(v) if QR, 0 otherwise */
        if (!bn_msqrt(ok, v, G_CTX)) {
            /* v is non-QR: invalid point */
            goto done;
        }
        /* v = 1/ok (= 1/sqrt(v)) */
        BN_mod_inverse(v, ok, G_P, G_CTX);
        BN_one(ok);
    }

    /* w = u*v (= u / sqrt(v) when v!=0) */
    FE_MUL(w, u, v);
    decaf_neg_if(w, w, G_CTX);

    /* tmp5 = w*s */
    FE_MUL(tmp5, w, s_bn);
    /* tmp6 = 2 - Z */
    BN_set_word(tmp4, 2);
    FE_SUB(tmp6, tmp4, Z);
    FE_MUL(w, tmp5, tmp6);  /* w = w*s*(2-Z) */

    /* Special case: s=0, add 1 */
    if (BN_is_zero(s_bn)) {
        FE_ADD(w, w, BN_value_one());
    }

    /* X = 2*s */
    FE_ADD(P->X, s_bn, s_bn);
    /* Y = w*Z */
    FE_MUL(P->Y, w, Z);
    /* T = w*X = w*2s */
    FE_MUL(P->T, w, P->X);
    /* Z = Z (already set) */
    BN_copy(P->Z, Z);

    ret = 0;

done:
    BN_free(s_bn); BN_free(ss); BN_free(u); BN_free(v); BN_free(w);
    BN_free(Z); BN_free(ok);
    BN_free(tmp1); BN_free(tmp2); BN_free(tmp3); BN_free(tmp4);
    BN_free(tmp5); BN_free(tmp6); BN_free(half);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Elligator2 hash-to-curve                                            */
/* ------------------------------------------------------------------ */

/*
 * elligator2: map field element r0 to extended point, using non-square n.
 * Ported from 9front elligator2.mpc.
 * All operations are mod p.
 */
static int elligator2(Pt448 *out, const BIGNUM *n, const BIGNUM *r0)
{
    BIGNUM *r, *N, *D, *ND, *c, *e, *s, *t;
    BIGNUM *tmp1, *tmp2, *tmp3, *tmp4, *tmp5, *tmp6;
    int ok = 0;

    r=BN_new(); N=BN_new(); D=BN_new(); ND=BN_new();
    c=BN_new(); e=BN_new(); s=BN_new(); t=BN_new();
    tmp1=BN_new(); tmp2=BN_new(); tmp3=BN_new(); tmp4=BN_new(); tmp5=BN_new(); tmp6=BN_new();
    if (!r||!N||!D||!ND||!c||!e||!s||!t||!tmp1||!tmp2||!tmp3||!tmp4||!tmp5||!tmp6)
        goto done;

    /* r = n * r0^2 */
    FE_SQR(tmp1, r0);
    FE_MUL(r, n, tmp1);

    /* D = (d*r + a - d) * (d*r - a*r - d) */
    /* d*r */
    FE_MUL(tmp1, G_D, r);
    /* tmp1 = d*r + a - d */
    FE_ADD(tmp1, tmp1, G_A);
    FE_SUB(tmp1, tmp1, G_D);
    /* d*r */
    FE_MUL(tmp2, G_D, r);
    /* a*r */
    FE_MUL(tmp3, G_A, r);
    /* tmp2 = d*r - a*r - d */
    FE_SUB(tmp2, tmp2, tmp3);
    FE_SUB(tmp2, tmp2, G_D);
    FE_MUL(D, tmp1, tmp2);

    /* N = (r+1) * (a - 2*d) */
    FE_ADD(tmp2, r, BN_value_one());
    /* 2*d */
    FE_ADD(tmp1, G_D, G_D);
    /* a - 2*d */
    FE_SUB(tmp1, G_A, tmp1);
    FE_MUL(N, tmp2, tmp1);

    /* ND = N*D */
    FE_MUL(ND, N, D);

    if (BN_is_zero(ND)) {
        BN_one(c);
        BN_zero(e);
    } else {
        /* e = sqrt(ND) if QR */
        if (bn_msqrt(e, ND, G_CTX)) {
            BN_one(c);
            BN_mod_inverse(e, e, G_P, G_CTX);  /* e = 1/sqrt(ND) */
        } else {
            /* Non-QR case: c = -1, e = n*r0 * misqrt(n*ND) */
            BN_mod_sub(c, G_P, BN_value_one(), G_P, G_CTX);  /* c = -1 mod p */
            FE_MUL(tmp4, n, r0);           /* tmp4 = n*r0 */
            FE_MUL(tmp6, n, ND);           /* tmp6 = n*ND */
            bn_misqrt(tmp5, tmp6, G_CTX);  /* tmp5 = misqrt(n*ND) */
            FE_MUL(e, tmp4, tmp5);         /* e = n*r0 * misqrt(n*ND) */
        }
    }

    /* s = c*N*e */
    FE_MUL(tmp1, c, N);
    FE_MUL(s, tmp1, e);

    /* t = c*N*(r-1) * ((a-2*d)*e)^2 - 1 */
    FE_MUL(tmp2, c, N);
    FE_SUB(tmp3, r, BN_value_one());
    FE_MUL(tmp1, tmp2, tmp3);

    FE_ADD(tmp2, G_D, G_D);
    FE_SUB(tmp2, G_A, tmp2);   /* a-2d */
    FE_MUL(tmp3, tmp2, e);     /* (a-2d)*e */
    FE_SQR(tmp3, tmp3);        /* ((a-2d)*e)^2 */
    FE_MUL(t, tmp1, tmp3);
    BN_mod_sub(t, G_P, t, G_P, G_CTX);  /* t = -t */
    FE_SUB(t, t, BN_value_one());

    /* X = 2*s*t */
    FE_ADD(tmp3, s, s);
    FE_MUL(out->X, tmp3, t);

    /* Y = (a*s^2 - 1) * (a*s^2 + 1) */
    FE_SQR(tmp3, s);
    FE_MUL(tmp3, G_A, tmp3);   /* a*s^2 */
    FE_SUB(tmp1, tmp3, BN_value_one());  /* a*s^2 - 1 */
    FE_ADD(tmp2, tmp3, BN_value_one());  /* a*s^2 + 1 */
    FE_MUL(out->Y, tmp1, tmp2);

    /* Z = (a*s^2 + 1) * t */
    FE_MUL(out->Z, tmp2, t);

    /* T = 2*s * (a*s^2 - 1) */
    FE_ADD(tmp3, s, s);
    FE_MUL(out->T, tmp3, tmp1);

    ok = 1;
done:
    BN_free(r); BN_free(N); BN_free(D); BN_free(ND);
    BN_free(c); BN_free(e); BN_free(s); BN_free(t);
    BN_free(tmp1); BN_free(tmp2); BN_free(tmp3);
    BN_free(tmp4); BN_free(tmp5); BN_free(tmp6);
    return ok ? 0 : -1;
}

/*
 * spake2ee_h2P: hash field element h to a curve point.
 * 1. Find smallest non-square n >= 2 (precomputed in G_NONSQR).
 * 2. Reduce h mod p.
 * 3. Call elligator2(n, h mod p) -> point.
 * Ported from 9front spake2ee.mpc:spake2ee_h2P.
 */
static int spake2ee_h2P(Pt448 *out, const BIGNUM *h)
{
    BIGNUM *hmod;
    int ret;

    hmod = BN_new();
    if (!hmod) return -1;
    BN_nnmod(hmod, h, G_P, G_CTX);
    ret = elligator2(out, G_NONSQR, hmod);
    BN_free(hmod);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  SPAKE2-EE operations (authpak_new / authpak_finish helpers)         */
/* ------------------------------------------------------------------ */

/*
 * spake2ee_1: generate blinded PAK key.
 *   y = Decaf(x*G + P)
 * where G is the base point and P is the blinding point (PM or PN).
 * x: 56-byte big-endian scalar.
 * PX,PY,PZ,PT: blinding point in extended coordinates.
 * y_out: 56-byte Decaf-encoded output.
 */
static int spake2ee_1(unsigned char y_out[AUTH_PAKYLEN],
                      const BIGNUM *x,
                      const Pt448 *G_pt, const Pt448 *P_blind)
{
    Pt448 *xG, *result, *tmp;
    int ret = -1;

    xG = pt_new(); result = pt_new(); tmp = pt_new();
    if (!xG || !result || !tmp) {
        pt_free(xG); pt_free(result); pt_free(tmp); return -1;
    }

    /* xG = x * G_pt */
    if (pt_scalarmul(xG, x, G_pt) < 0) goto done;
    /* result = xG + P_blind */
    if (pt_add(result, xG, P_blind) < 0) goto done;
    /* Decaf encode */
    if (decaf_encode_pt(y_out, result) < 0) goto done;

    ret = 0;
done:
    pt_free(xG); pt_free(result); pt_free(tmp);
    return ret;
}

/*
 * spake2ee_2: compute shared secret.
 *   z = Decaf(x * (Decaf_decode(y_peer) - P_blind))
 * x: 56-byte big-endian scalar.
 * y_peer: peer's Decaf-encoded key.
 * P_blind: the peer's blinding point (PN for client, PM for server).
 * Returns 0 on success (ok), -1 on failure (invalid peer key).
 */
static int spake2ee_2(unsigned char z_out[AUTH_PAKSLEN],
                      const BIGNUM *x,
                      const unsigned char y_peer[AUTH_PAKYLEN],
                      const Pt448 *P_blind)
{
    Pt448 *Y, *negP, *unblinded, *result;
    int ret = -1;

    Y = pt_new(); negP = pt_new(); unblinded = pt_new(); result = pt_new();
    if (!Y || !negP || !unblinded || !result) {
        pt_free(Y); pt_free(negP); pt_free(unblinded); pt_free(result);
        return -1;
    }

    /* Decode peer's Decaf key */
    if (decaf_decode_pt(Y, y_peer) < 0) goto done;

    /* Negate blinding point: -P = (-PX : PY : PZ : -PT) */
    BN_mod_sub(negP->X, G_P, P_blind->X, G_P, G_CTX);
    BN_copy(negP->Y, P_blind->Y);
    BN_copy(negP->Z, P_blind->Z);
    BN_mod_sub(negP->T, G_P, P_blind->T, G_P, G_CTX);

    /* unblinded = Y + (-P) = Y - P */
    if (pt_add(unblinded, Y, negP) < 0) goto done;

    /* result = x * unblinded */
    if (pt_scalarmul(result, x, unblinded) < 0) goto done;

    /* Decaf encode shared secret */
    if (decaf_encode_pt(z_out, result) < 0) goto done;

    ret = 0;
done:
    pt_free(Y); pt_free(negP); pt_free(unblinded); pt_free(result);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Key derivation                                                      */
/* ------------------------------------------------------------------ */

/*
 * passtoaeskey: PBKDF2-HMAC-SHA1 with salt="Plan 9 key derivation", 9001 iterations.
 * Matches 9front libauthsrv/passtokey.c:passtoaeskey.
 */
static int passtoaeskey(unsigned char aes[AUTH_AESKEYLEN], const char *password)
{
    static const char salt[] = "Plan 9 key derivation";
    return PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        (const unsigned char*)salt, (int)(sizeof(salt)-1),
        9001,
        EVP_sha1(),
        AUTH_AESKEYLEN, aes) == 1 ? 0 : -1;
}

/*
 * hkdf_x: HKDF extract+expand using HMAC-SHA256.
 * Matches Plan 9 libsec hkdf_x(salt, saltlen, info, infolen, ikm, ikmlen, okm, okmlen, ...).
 * This is standard RFC 5869 HKDF.
 */
static int hkdf_x(const unsigned char *salt, int saltlen,
                  const unsigned char *info, int infolen,
                  const unsigned char *ikm, int ikmlen,
                  unsigned char *okm, int okmlen)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[6];
    int ret;
    char digest[] = "SHA-256";

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return -1;

    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void*)ikm, (size_t)ikmlen);
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void*)salt, (size_t)saltlen);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void*)info, (size_t)infolen);
    params[4] = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, okm, (size_t)okmlen, params) == 1 ? 0 : -1;
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  AuthPAK public API                                                  */
/* ------------------------------------------------------------------ */

/*
 * authpak_hash: derive blinding points PM and PN from password (via AES key) + username.
 * Fills k->pakhash[448] = PM(X,Y,Z,T)[224] || PN(X,Y,Z,T)[224].
 * Matches 9front authpak.c:authpak_hash exactly.
 */
int authpak_hash(Authkey *k, const char *user)
{
    static const char info[] = "Plan 9 AuthPAK hash";
    unsigned char salt[32], h[2*AUTH_PAKSLEN];
    BIGNUM *H;
    Pt448 *P;
    unsigned char *bp;
    int i;

    if (!G_initialized && ed448_init() < 0) return -1;

    /* salt = SHA256(user) */
    {
        unsigned int mdlen = 32;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, (const unsigned char*)user, strlen(user));
        EVP_DigestFinal_ex(ctx, salt, &mdlen);
        EVP_MD_CTX_free(ctx);
    }

    /* h[112] = hkdf_x(salt, 32, info, 19, aes, 16, 112) */
    if (hkdf_x(salt, 32, (const unsigned char*)info, (int)(sizeof(info)-1),
                k->aes, AUTH_AESKEYLEN, h, 2*AUTH_PAKSLEN) < 0)
        return -1;

    H = BN_new();
    P = pt_new();
    if (!H || !P) { BN_free(H); pt_free(P); return -1; }

    bp = k->pakhash;

    /* HM = betomp(h[0..55]) → h2P → PM stored as (X,Y,Z,T) each 56 bytes big-endian */
    BN_bin2bn(h + 0*AUTH_PAKSLEN, AUTH_PAKSLEN, H);
    if (spake2ee_h2P(P, H) < 0) goto err;
    for (i = 0; i < 4; i++) {
        BIGNUM *coord[4] = { P->X, P->Y, P->Z, P->T };
        memset(bp, 0, AUTH_PAKSLEN);
        {
            int nb = BN_num_bytes(coord[i]);
            if (nb <= AUTH_PAKSLEN)
                BN_bn2bin(coord[i], bp + (AUTH_PAKSLEN - nb));
        }
        bp += AUTH_PAKSLEN;
    }

    /* HN = betomp(h[56..111]) → h2P → PN */
    BN_bin2bn(h + 1*AUTH_PAKSLEN, AUTH_PAKSLEN, H);
    if (spake2ee_h2P(P, H) < 0) goto err;
    for (i = 0; i < 4; i++) {
        BIGNUM *coord[4] = { P->X, P->Y, P->Z, P->T };
        memset(bp, 0, AUTH_PAKSLEN);
        {
            int nb = BN_num_bytes(coord[i]);
            if (nb <= AUTH_PAKSLEN)
                BN_bn2bin(coord[i], bp + (AUTH_PAKSLEN - nb));
        }
        bp += AUTH_PAKSLEN;
    }

    BN_free(H); pt_free(P);
    return 0;
err:
    BN_free(H); pt_free(P);
    return -1;
}

/*
 * Load blinding point from pakhash buffer (big-endian 4*56 bytes: X,Y,Z,T).
 * offset = 0 for PM, AUTH_PAKPLEN for PN.
 */
static int load_pakpoint(Pt448 *P, const unsigned char *pakhash, int offset)
{
    const unsigned char *bp = pakhash + offset;
    BN_bin2bn(bp + 0*AUTH_PAKSLEN, AUTH_PAKSLEN, P->X);
    BN_bin2bn(bp + 1*AUTH_PAKSLEN, AUTH_PAKSLEN, P->Y);
    BN_bin2bn(bp + 2*AUTH_PAKSLEN, AUTH_PAKSLEN, P->Z);
    BN_bin2bn(bp + 3*AUTH_PAKSLEN, AUTH_PAKSLEN, P->T);
    return 0;
}

/*
 * authpak_new: generate blinded PAK key.
 *   isclient=1 → client role: blinding with PM (pakhash[0])
 *   isclient=0 → server role: blinding with PN (pakhash[AUTH_PAKPLEN])
 *
 * Fills p->x (random scalar), p->y (our blinded Decaf key).
 * Copies y to y_out[AUTH_PAKYLEN].
 * Matches 9front authpak.c:authpak_new.
 */
int authpak_new(PAKpriv *p, Authkey *k, unsigned char y_out[AUTH_PAKYLEN], int isclient)
{
    BIGNUM *X;
    Pt448 *G_pt, *P_blind;
    int blind_offset;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    memset(p, 0, sizeof(*p));
    p->isclient = (isclient != 0);

    /* isclient=1 uses PM (offset 0), isclient=0 uses PN (offset AUTH_PAKPLEN) */
    blind_offset = p->isclient ? 0 : AUTH_PAKPLEN;

    X = BN_new();
    G_pt = pt_new();
    P_blind = pt_new();
    if (!X || !G_pt || !P_blind) {
        BN_free(X); pt_free(G_pt); pt_free(P_blind); return -1;
    }

    /* Load base point G */
    BN_copy(G_pt->X, G_GX);
    BN_copy(G_pt->Y, G_GY);
    BN_one(G_pt->Z);
    FE_MUL(G_pt->T, G_pt->X, G_pt->Y);

    /* Load blinding point P from pakhash */
    load_pakpoint(P_blind, k->pakhash, blind_offset);

    /* Generate random scalar X in [0, P) */
    do {
        BN_rand_range(X, G_P);
    } while (BN_is_zero(X));

    /* Store x as 56-byte big-endian */
    memset(p->x, 0, AUTH_PAKXLEN);
    {
        int nb = BN_num_bytes(X);
        if (nb <= AUTH_PAKXLEN)
            BN_bn2bin(X, p->x + (AUTH_PAKXLEN - nb));
    }

    /* y = Decaf(X*G + P_blind) */
    if (spake2ee_1(p->y, X, G_pt, P_blind) < 0) goto done;

    memcpy(y_out, p->y, AUTH_PAKYLEN);
    ret = 0;

done:
    BN_free(X); pt_free(G_pt); pt_free(P_blind);
    return ret;
}

/*
 * authpak_finish: compute shared secret and derive pakkey.
 *   isclient=1: uses PN to unmask peer (blind_offset = AUTH_PAKPLEN)
 *   isclient=0: uses PM to unmask peer (blind_offset = 0)
 *
 * salt = SHA256(my_y || peer_y)  for client (isclient=1)
 * salt = SHA256(peer_y || my_y)  for server (isclient=0)
 *   (always: SHA256(client_key || server_key))
 *
 * pakkey = hkdf_x(salt, "Plan 9 AuthPAK key", z, 32)
 * Returns 0 on success, -1 on failure.
 */
int authpak_finish(PAKpriv *p, Authkey *k, const unsigned char y_peer[AUTH_PAKYLEN])
{
    static const char info[] = "Plan 9 AuthPAK key";
    BIGNUM *X;
    Pt448 *P_blind;
    unsigned char z[AUTH_PAKSLEN], salt[32];
    int blind_offset;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    /* isclient=1 finish uses PN (offset AUTH_PAKPLEN) to unmask peer */
    /* isclient=0 finish uses PM (offset 0) to unmask peer */
    blind_offset = p->isclient ? AUTH_PAKPLEN : 0;

    X = BN_new();
    P_blind = pt_new();
    if (!X || !P_blind) { BN_free(X); pt_free(P_blind); return -1; }

    /* Load our private scalar */
    BN_bin2bn(p->x, AUTH_PAKXLEN, X);

    /* Load peer's blinding point */
    load_pakpoint(P_blind, k->pakhash, blind_offset);

    /* z = Decaf(X * (peer_key - P_blind)) */
    if (spake2ee_2(z, X, y_peer, P_blind) < 0) goto done;

    /* salt = SHA256(client_key || server_key) */
    {
        unsigned int mdlen = 32;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        const unsigned char *client_key = p->isclient ? p->y : y_peer;
        const unsigned char *server_key = p->isclient ? y_peer : p->y;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, client_key, AUTH_PAKYLEN);
        EVP_DigestUpdate(ctx, server_key, AUTH_PAKYLEN);
        EVP_DigestFinal_ex(ctx, salt, &mdlen);
        EVP_MD_CTX_free(ctx);
    }

    /* pakkey = hkdf_x(salt, "Plan 9 AuthPAK key", z, 32) */
    if (hkdf_x(salt, 32, (const unsigned char*)info, (int)(sizeof(info)-1),
                z, AUTH_PAKSLEN, k->pakkey, AUTH_PAKKEYLEN) < 0)
        goto done;

    ret = 0;
done:
    memset(z, 0, sizeof(z));
    memset(p, 0, sizeof(*p));
    BN_free(X); pt_free(P_blind);
    return ret;
}

/*
 * passtokey: derive Authkey from plaintext password.
 * Fills k->des (DES key) and k->aes (PBKDF2-SHA1 key).
 * Matches 9front libauthsrv/passtokey.c:passtokey.
 */
int passtokey(Authkey *k, const char *password)
{
    unsigned char buf[28];
    int n, i;
    const unsigned char *t;

    memset(k, 0, sizeof(*k));

    /* passtodeskey: simplified DES key derivation */
    memset(buf, ' ', 8);
    n = (int)strlen(password);
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    memcpy(buf, (const unsigned char*)password, (size_t)n);
    buf[n] = 0;
    memset(k->des, 0, AUTH_DESKEYLEN);
    t = buf;
    for (;;) {
        for (i = 0; i < AUTH_DESKEYLEN; i++)
            k->des[i] = (char)((t[i] >> i) + (t[i+1] << (8 - (i+1))));
        if (n <= 8) break;
        n -= 8; t += 8;
        if (n < 8) { t -= 8 - n; n = 8; }
        /* Note: plan 9 DES-encrypts here; we skip for dp9ik (we only need aes) */
        break;
    }

    /* passtoaeskey */
    if (passtoaeskey(k->aes, password) < 0) return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Initialization / cleanup                                            */
/* ------------------------------------------------------------------ */

int ed448_init(void)
{
    BIGNUM *two, *tmp;
    int leg;

    if (G_initialized) return 0;

    G_CTX = BN_CTX_new();
    G_P = BN_new(); G_A = BN_new(); G_D = BN_new();
    G_GX = BN_new(); G_GY = BN_new(); G_N = BN_new();
    G_NONSQR = BN_new(); G_SQRT_EXP = BN_new(); G_ISQRT_EXP = BN_new();
    if (!G_CTX||!G_P||!G_A||!G_D||!G_GX||!G_GY||!G_N||!G_NONSQR||!G_SQRT_EXP||!G_ISQRT_EXP)
        goto err;

    if (!BN_hex2bn(&G_P, P448_HEX)) goto err;
    BN_one(G_A);
    if (!BN_hex2bn(&G_D, D448_HEX)) goto err;
    if (!BN_hex2bn(&G_GX, GX_HEX)) goto err;
    BN_set_word(G_GY, 19);
    if (!BN_hex2bn(&G_N, N448_HEX)) goto err;

    /* SQRT_EXP = (p+1)/4 */
    tmp = BN_new();
    BN_copy(tmp, G_P);
    BN_add_word(tmp, 1);
    BN_rshift(G_SQRT_EXP, tmp, 2);

    /* ISQRT_EXP = (p-3)/4 */
    BN_copy(tmp, G_P);
    BN_sub_word(tmp, 3);
    BN_rshift(G_ISQRT_EXP, tmp, 2);
    BN_free(tmp);

    /* Find smallest non-square n >= 2 */
    two = BN_new();
    BN_set_word(two, 2);
    BN_copy(G_NONSQR, two);
    BN_free(two);
    for (;;) {
        leg = bn_legendre(G_NONSQR, G_CTX);
        if (leg == -1) break;  /* found non-QR */
        BN_add_word(G_NONSQR, 1);
    }

    G_initialized = 1;
    fprintf(stderr, "ed448: initialized (Goldilocks a=1, Decaf encoding, non-QR=%s)\n",
            BN_bn2dec(G_NONSQR));
    return 0;

err:
    ed448_cleanup();
    return -1;
}

void ed448_cleanup(void)
{
    if (!G_initialized) return;
    BN_free(G_P); BN_free(G_A); BN_free(G_D);
    BN_free(G_GX); BN_free(G_GY); BN_free(G_N);
    BN_free(G_NONSQR); BN_free(G_SQRT_EXP); BN_free(G_ISQRT_EXP);
    BN_CTX_free(G_CTX);
    G_P=G_A=G_D=G_GX=G_GY=G_N=G_NONSQR=G_SQRT_EXP=G_ISQRT_EXP=NULL;
    G_CTX=NULL;
    G_initialized = 0;
}

/* ------------------------------------------------------------------ */
/*  Legacy API (kept for compatibility, use Decaf variants now)         */
/* ------------------------------------------------------------------ */

int ed448_scalar_generate(unsigned char scalar[AUTH_PAKXLEN])
{
    BIGNUM *x;
    int ret = -1;
    if (!G_initialized && ed448_init() < 0) return -1;
    x = BN_new();
    if (!x) return -1;
    do { BN_rand_range(x, G_P); } while (BN_is_zero(x));
    memset(scalar, 0, AUTH_PAKXLEN);
    {
        int nb = BN_num_bytes(x);
        if (nb <= AUTH_PAKXLEN) { BN_bn2bin(x, scalar + (AUTH_PAKXLEN - nb)); ret = 0; }
    }
    BN_free(x);
    return ret;
}

int ed448_scalarmult(unsigned char out[AUTH_PAKYLEN],
                     const unsigned char scalar[AUTH_PAKXLEN],
                     const unsigned char point[AUTH_PAKYLEN])
{
    Pt448 *P, *R;
    BIGNUM *sc;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    sc = BN_bin2bn(scalar, AUTH_PAKXLEN, NULL);
    P = pt_new(); R = pt_new();
    if (!sc || !P || !R) { BN_free(sc); pt_free(P); pt_free(R); return -1; }

    if (decaf_decode_pt(P, point) < 0) goto done;
    if (pt_scalarmul(R, sc, P) < 0) goto done;
    if (decaf_encode_pt(out, R) < 0) goto done;
    ret = 0;
done:
    BN_free(sc); pt_free(P); pt_free(R);
    return ret;
}

/*
 * Compute public key from private scalar: pub = scalar * G (base point).
 */
int ed448_scalarmult_base(unsigned char pub[AUTH_PAKYLEN],
                          const unsigned char scalar[AUTH_PAKXLEN])
{
    Pt448 *G_pt, *R;
    BIGNUM *sc;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    sc = BN_bin2bn(scalar, AUTH_PAKXLEN, NULL);
    G_pt = pt_new(); R = pt_new();
    if (!sc || !G_pt || !R) { BN_free(sc); pt_free(G_pt); pt_free(R); return -1; }

    /* Load base point G */
    BN_copy(G_pt->X, G_GX);
    BN_copy(G_pt->Y, G_GY);
    BN_one(G_pt->Z);
    FE_MUL(G_pt->T, G_pt->X, G_pt->Y);

    /* R = scalar * G */
    if (pt_scalarmul(R, sc, G_pt) < 0) goto done;
    if (decaf_encode_pt(pub, R) < 0) goto done;
    ret = 0;
done:
    BN_free(sc); pt_free(G_pt); pt_free(R);
    return ret;
}

/*
 * Hash data to a curve point using Elligator2.
 * For password masking in PAK protocol.
 */
int ed448_hash_to_point(unsigned char out[AUTH_PAKYLEN],
                        const unsigned char *data, size_t len)
{
    Pt448 *R;
    BIGNUM *h;
    unsigned char hash[64];
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    /* Hash the input data using SHA-512 */
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha512();
        unsigned int hash_len = sizeof(hash);

        if (!mdctx) return -1;
        if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
            EVP_DigestUpdate(mdctx, data, len) != 1 ||
            EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
        EVP_MD_CTX_free(mdctx);
    }

    /* Reduce hash modulo field prime p */
    h = BN_bin2bn(hash, sizeof(hash), NULL);
    R = pt_new();
    if (!h || !R) { BN_free(h); pt_free(R); return -1; }

    if (BN_mod(h, h, G_P, G_CTX) != 1) goto done;

    /* Use Elligator2 to map to curve point */
    if (spake2ee_h2P(R, h) < 0) goto done;
    if (decaf_encode_pt(out, R) < 0) goto done;
    ret = 0;

done:
    BN_free(h); pt_free(R);
    return ret;
}

int ed448_point_add(unsigned char out[AUTH_PAKYLEN],
                    const unsigned char A[AUTH_PAKYLEN],
                    const unsigned char B[AUTH_PAKYLEN])
{
    Pt448 *PA, *PB, *R;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    PA=pt_new(); PB=pt_new(); R=pt_new();
    if (!PA||!PB||!R) { pt_free(PA); pt_free(PB); pt_free(R); return -1; }

    if (decaf_decode_pt(PA, A) < 0 || decaf_decode_pt(PB, B) < 0) goto done;
    if (pt_add(R, PA, PB) < 0) goto done;
    if (decaf_encode_pt(out, R) < 0) goto done;
    ret = 0;
done:
    pt_free(PA); pt_free(PB); pt_free(R);
    return ret;
}

int ed448_point_sub(unsigned char out[AUTH_PAKYLEN],
                    const unsigned char A[AUTH_PAKYLEN],
                    const unsigned char B[AUTH_PAKYLEN])
{
    Pt448 *PA, *PB, *negB, *R;
    int ret = -1;

    if (!G_initialized && ed448_init() < 0) return -1;

    PA=pt_new(); PB=pt_new(); negB=pt_new(); R=pt_new();
    if (!PA||!PB||!negB||!R) { pt_free(PA); pt_free(PB); pt_free(negB); pt_free(R); return -1; }

    if (decaf_decode_pt(PA, A) < 0 || decaf_decode_pt(PB, B) < 0) goto done;
    BN_mod_sub(negB->X, G_P, PB->X, G_P, G_CTX);
    BN_copy(negB->Y, PB->Y);
    BN_copy(negB->Z, PB->Z);
    BN_mod_sub(negB->T, G_P, PB->T, G_P, G_CTX);
    if (pt_add(R, PA, negB) < 0) goto done;
    if (decaf_encode_pt(out, R) < 0) goto done;
    ret = 0;
done:
    pt_free(PA); pt_free(PB); pt_free(negB); pt_free(R);
    return ret;
}

int ed448_point_valid(const unsigned char point[AUTH_PAKYLEN])
{
    Pt448 *P;
    int valid;
    if (!G_initialized && ed448_init() < 0) return 0;
    P = pt_new();
    if (!P) return 0;
    valid = (decaf_decode_pt(P, point) == 0) ? 1 : 0;
    pt_free(P);
    return valid;
}

#else /* !USE_OPENSSL */

int ed448_init(void) { return -1; }
void ed448_cleanup(void) {}
int ed448_scalar_generate(unsigned char *s) { (void)s; return -1; }
int ed448_scalarmult(unsigned char *o, const unsigned char *s, const unsigned char *p)
    { (void)o; (void)s; (void)p; return -1; }
int ed448_point_add(unsigned char *o, const unsigned char *a, const unsigned char *b)
    { (void)o; (void)a; (void)b; return -1; }
int ed448_point_sub(unsigned char *o, const unsigned char *a, const unsigned char *b)
    { (void)o; (void)a; (void)b; return -1; }
int ed448_point_valid(const unsigned char *p) { (void)p; return 0; }
int ed448_scalarmult_base(unsigned char *o, const unsigned char *s)
    { (void)o; (void)s; return -1; }
int ed448_hash_to_point(unsigned char *o, const unsigned char *d, size_t l)
    { (void)o; (void)d; (void)l; return -1; }
int authpak_hash(Authkey *k, const char *user) { (void)k; (void)user; return -1; }
int authpak_new(PAKpriv *p, Authkey *k, unsigned char *y, int c) { (void)p;(void)k;(void)y;(void)c; return -1; }
int authpak_finish(PAKpriv *p, Authkey *k, const unsigned char *y) { (void)p;(void)k;(void)y; return -1; }
int passtokey(Authkey *k, const char *pw) { (void)k; (void)pw; return -1; }

#endif /* USE_OPENSSL */
