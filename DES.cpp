/*
 * -----------------------------------------------------------------------------
 * -----                              DES.C                                -----
 * -----                             EASYPAY                               -----
 * -----------------------------------------------------------------------------
 *
 * File Description:
 *   This is a library of functions for basic DES crypto operations
 *
 * Table of Contents:
 *   DES_set_key     - Create DES key schedule
 *   DES_ecb_encrypt - Basic DES encryption routine
 *   encrypt1    - core subroutine. Called by all routines
 *
 * Copyright:
 *   This file includes and is based off of DES cryptographic software written 
 *   by Eric Young (eay@cryptsoft.com)
 *
 * Converted from C to C++ by Elmü 2016
 *
 * Compiler:
 *   HI-TECH C Compiler for PIC18 MCUs (http://www.htsoft.com/)
 *
 * Revision History:
 *   Jan. 06, 2013      Nnoduka Eruchalu     Initial Revision
 *   Jan. 18, 2013      Nnoduka Eruchalu     Added DES_set_key
 */

#include "DES.h"
#include "Utils.h"

#define c2l(c,l)  (l =((DES_LONG)(*((c)++)))    , \
       l|=((DES_LONG)(*((c)++)))<< 8L, \
       l|=((DES_LONG)(*((c)++)))<<16L, \
       l|=((DES_LONG)(*((c)++)))<<24L)

#define l2c(l,c)  (*((c)++)=(unsigned char)(((l)     )&0xff), \
       *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
       *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
       *((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define ROTATE(a,n) (((a)>>(n))+((a)<<(32-(n))))

#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
  u=R^s[S  ]; \
  t=R^s[S+1]

#define D_ENCRYPT(LL,R,S) {\
  LOAD_DATA_tmp(R,S,u,t,E0,E1); \
  t=ROTATE(t,4); \
  LL^=\
    DES_SPtrans[0][(u>> 2L)&0x3f]^ \
    DES_SPtrans[2][(u>>10L)&0x3f]^ \
    DES_SPtrans[4][(u>>18L)&0x3f]^ \
    DES_SPtrans[6][(u>>26L)&0x3f]^ \
    DES_SPtrans[1][(t>> 2L)&0x3f]^ \
    DES_SPtrans[3][(t>>10L)&0x3f]^ \
    DES_SPtrans[5][(t>>18L)&0x3f]^ \
    DES_SPtrans[7][(t>>26L)&0x3f]; }

  /* *********** Comments from original documentation: **************
         * IP and FP
   * The problem is more of a geometric problem that random bit fiddling.
   0  1  2  3  4  5  6  7      62 54 46 38 30 22 14  6
   8  9 10 11 12 13 14 15      60 52 44 36 28 20 12  4
  16 17 18 19 20 21 22 23      58 50 42 34 26 18 10  2
  24 25 26 27 28 29 30 31  to  56 48 40 32 24 16  8  0

  32 33 34 35 36 37 38 39      63 55 47 39 31 23 15  7
  40 41 42 43 44 45 46 47      61 53 45 37 29 21 13  5
  48 49 50 51 52 53 54 55      59 51 43 35 27 19 11  3
  56 57 58 59 60 61 62 63      57 49 41 33 25 17  9  1

  The output has been subject to swaps of the form
  0 1 -> 3 1 but the odd and even bits have been put into
  2 3    2 0
  different words.  The main trick is to remember that
  t=((l>>size)^r)&(mask);
  r^=t;
  l^=(t<<size);
  can be used to swap and move bits between words.

  So l =  0  1  2  3  r = 16 17 18 19
          4  5  6  7      20 21 22 23
          8  9 10 11      24 25 26 27
         12 13 14 15      28 29 30 31
  becomes (for size == 2 and mask == 0x3333)
     t =   2^16  3^17 -- --   l =  0  1 16 17  r =  2  3 18 19
     6^20  7^21 -- --        4  5 20 21       6  7 22 23
    10^24 11^25 -- --        8  9 24 25      10 11 24 25
    14^28 15^29 -- --       12 13 28 29      14 15 28 29

  Thanks for hints from Richard Outerbridge - he told me IP&FP
  could be done in 15 xor, 10 shifts and 5 ands.
  When I finally started to think of the problem in 2D
  I first got ~42 operations without xors.  When I remembered
  how to use xors :-) I got it to its final state.
  */
#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
  (b)^=(t),\
  (a)^=((t)<<(n)))

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
  (a)=(a)^(t)^(t>>(16-(n))))

#define IP(l,r) \
  { \
  register DES_LONG tt; \
  PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
  PERM_OP(l,r,tt,16,0x0000ffffL); \
  PERM_OP(r,l,tt, 2,0x33333333L); \
  PERM_OP(l,r,tt, 8,0x00ff00ffL); \
  PERM_OP(r,l,tt, 1,0x55555555L); \
  }

#define FP(l,r) \
  { \
  register DES_LONG tt; \
  PERM_OP(l,r,tt, 1,0x55555555L); \
  PERM_OP(r,l,tt, 8,0x00ff00ffL); \
  PERM_OP(l,r,tt, 2,0x33333333L); \
  PERM_OP(r,l,tt,16,0x0000ffffL); \
  PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
  }

const DES_LONG DES_SPtrans[8][64]={
{
/* nibble 0 */
0x02080800L, 0x00080000L, 0x02000002L, 0x02080802L,
0x02000000L, 0x00080802L, 0x00080002L, 0x02000002L,
0x00080802L, 0x02080800L, 0x02080000L, 0x00000802L,
0x02000802L, 0x02000000L, 0x00000000L, 0x00080002L,
0x00080000L, 0x00000002L, 0x02000800L, 0x00080800L,
0x02080802L, 0x02080000L, 0x00000802L, 0x02000800L,
0x00000002L, 0x00000800L, 0x00080800L, 0x02080002L,
0x00000800L, 0x02000802L, 0x02080002L, 0x00000000L,
0x00000000L, 0x02080802L, 0x02000800L, 0x00080002L,
0x02080800L, 0x00080000L, 0x00000802L, 0x02000800L,
0x02080002L, 0x00000800L, 0x00080800L, 0x02000002L,
0x00080802L, 0x00000002L, 0x02000002L, 0x02080000L,
0x02080802L, 0x00080800L, 0x02080000L, 0x02000802L,
0x02000000L, 0x00000802L, 0x00080002L, 0x00000000L,
0x00080000L, 0x02000000L, 0x02000802L, 0x02080800L,
0x00000002L, 0x02080002L, 0x00000800L, 0x00080802L,
},{
/* nibble 1 */
0x40108010L, 0x00000000L, 0x00108000L, 0x40100000L,
0x40000010L, 0x00008010L, 0x40008000L, 0x00108000L,
0x00008000L, 0x40100010L, 0x00000010L, 0x40008000L,
0x00100010L, 0x40108000L, 0x40100000L, 0x00000010L,
0x00100000L, 0x40008010L, 0x40100010L, 0x00008000L,
0x00108010L, 0x40000000L, 0x00000000L, 0x00100010L,
0x40008010L, 0x00108010L, 0x40108000L, 0x40000010L,
0x40000000L, 0x00100000L, 0x00008010L, 0x40108010L,
0x00100010L, 0x40108000L, 0x40008000L, 0x00108010L,
0x40108010L, 0x00100010L, 0x40000010L, 0x00000000L,
0x40000000L, 0x00008010L, 0x00100000L, 0x40100010L,
0x00008000L, 0x40000000L, 0x00108010L, 0x40008010L,
0x40108000L, 0x00008000L, 0x00000000L, 0x40000010L,
0x00000010L, 0x40108010L, 0x00108000L, 0x40100000L,
0x40100010L, 0x00100000L, 0x00008010L, 0x40008000L,
0x40008010L, 0x00000010L, 0x40100000L, 0x00108000L,
},{
/* nibble 2 */
0x04000001L, 0x04040100L, 0x00000100L, 0x04000101L,
0x00040001L, 0x04000000L, 0x04000101L, 0x00040100L,
0x04000100L, 0x00040000L, 0x04040000L, 0x00000001L,
0x04040101L, 0x00000101L, 0x00000001L, 0x04040001L,
0x00000000L, 0x00040001L, 0x04040100L, 0x00000100L,
0x00000101L, 0x04040101L, 0x00040000L, 0x04000001L,
0x04040001L, 0x04000100L, 0x00040101L, 0x04040000L,
0x00040100L, 0x00000000L, 0x04000000L, 0x00040101L,
0x04040100L, 0x00000100L, 0x00000001L, 0x00040000L,
0x00000101L, 0x00040001L, 0x04040000L, 0x04000101L,
0x00000000L, 0x04040100L, 0x00040100L, 0x04040001L,
0x00040001L, 0x04000000L, 0x04040101L, 0x00000001L,
0x00040101L, 0x04000001L, 0x04000000L, 0x04040101L,
0x00040000L, 0x04000100L, 0x04000101L, 0x00040100L,
0x04000100L, 0x00000000L, 0x04040001L, 0x00000101L,
0x04000001L, 0x00040101L, 0x00000100L, 0x04040000L,
},{
/* nibble 3 */
0x00401008L, 0x10001000L, 0x00000008L, 0x10401008L,
0x00000000L, 0x10400000L, 0x10001008L, 0x00400008L,
0x10401000L, 0x10000008L, 0x10000000L, 0x00001008L,
0x10000008L, 0x00401008L, 0x00400000L, 0x10000000L,
0x10400008L, 0x00401000L, 0x00001000L, 0x00000008L,
0x00401000L, 0x10001008L, 0x10400000L, 0x00001000L,
0x00001008L, 0x00000000L, 0x00400008L, 0x10401000L,
0x10001000L, 0x10400008L, 0x10401008L, 0x00400000L,
0x10400008L, 0x00001008L, 0x00400000L, 0x10000008L,
0x00401000L, 0x10001000L, 0x00000008L, 0x10400000L,
0x10001008L, 0x00000000L, 0x00001000L, 0x00400008L,
0x00000000L, 0x10400008L, 0x10401000L, 0x00001000L,
0x10000000L, 0x10401008L, 0x00401008L, 0x00400000L,
0x10401008L, 0x00000008L, 0x10001000L, 0x00401008L,
0x00400008L, 0x00401000L, 0x10400000L, 0x10001008L,
0x00001008L, 0x10000000L, 0x10000008L, 0x10401000L,
},{
/* nibble 4 */
0x08000000L, 0x00010000L, 0x00000400L, 0x08010420L,
0x08010020L, 0x08000400L, 0x00010420L, 0x08010000L,
0x00010000L, 0x00000020L, 0x08000020L, 0x00010400L,
0x08000420L, 0x08010020L, 0x08010400L, 0x00000000L,
0x00010400L, 0x08000000L, 0x00010020L, 0x00000420L,
0x08000400L, 0x00010420L, 0x00000000L, 0x08000020L,
0x00000020L, 0x08000420L, 0x08010420L, 0x00010020L,
0x08010000L, 0x00000400L, 0x00000420L, 0x08010400L,
0x08010400L, 0x08000420L, 0x00010020L, 0x08010000L,
0x00010000L, 0x00000020L, 0x08000020L, 0x08000400L,
0x08000000L, 0x00010400L, 0x08010420L, 0x00000000L,
0x00010420L, 0x08000000L, 0x00000400L, 0x00010020L,
0x08000420L, 0x00000400L, 0x00000000L, 0x08010420L,
0x08010020L, 0x08010400L, 0x00000420L, 0x00010000L,
0x00010400L, 0x08010020L, 0x08000400L, 0x00000420L,
0x00000020L, 0x00010420L, 0x08010000L, 0x08000020L,
},{
/* nibble 5 */
0x80000040L, 0x00200040L, 0x00000000L, 0x80202000L,
0x00200040L, 0x00002000L, 0x80002040L, 0x00200000L,
0x00002040L, 0x80202040L, 0x00202000L, 0x80000000L,
0x80002000L, 0x80000040L, 0x80200000L, 0x00202040L,
0x00200000L, 0x80002040L, 0x80200040L, 0x00000000L,
0x00002000L, 0x00000040L, 0x80202000L, 0x80200040L,
0x80202040L, 0x80200000L, 0x80000000L, 0x00002040L,
0x00000040L, 0x00202000L, 0x00202040L, 0x80002000L,
0x00002040L, 0x80000000L, 0x80002000L, 0x00202040L,
0x80202000L, 0x00200040L, 0x00000000L, 0x80002000L,
0x80000000L, 0x00002000L, 0x80200040L, 0x00200000L,
0x00200040L, 0x80202040L, 0x00202000L, 0x00000040L,
0x80202040L, 0x00202000L, 0x00200000L, 0x80002040L,
0x80000040L, 0x80200000L, 0x00202040L, 0x00000000L,
0x00002000L, 0x80000040L, 0x80002040L, 0x80202000L,
0x80200000L, 0x00002040L, 0x00000040L, 0x80200040L,
},{
/* nibble 6 */
0x00004000L, 0x00000200L, 0x01000200L, 0x01000004L,
0x01004204L, 0x00004004L, 0x00004200L, 0x00000000L,
0x01000000L, 0x01000204L, 0x00000204L, 0x01004000L,
0x00000004L, 0x01004200L, 0x01004000L, 0x00000204L,
0x01000204L, 0x00004000L, 0x00004004L, 0x01004204L,
0x00000000L, 0x01000200L, 0x01000004L, 0x00004200L,
0x01004004L, 0x00004204L, 0x01004200L, 0x00000004L,
0x00004204L, 0x01004004L, 0x00000200L, 0x01000000L,
0x00004204L, 0x01004000L, 0x01004004L, 0x00000204L,
0x00004000L, 0x00000200L, 0x01000000L, 0x01004004L,
0x01000204L, 0x00004204L, 0x00004200L, 0x00000000L,
0x00000200L, 0x01000004L, 0x00000004L, 0x01000200L,
0x00000000L, 0x01000204L, 0x01000200L, 0x00004200L,
0x00000204L, 0x00004000L, 0x01004204L, 0x01000000L,
0x01004200L, 0x00000004L, 0x00004004L, 0x01004204L,
0x01000004L, 0x01004200L, 0x01004000L, 0x00004004L,
},{
/* nibble 7 */
0x20800080L, 0x20820000L, 0x00020080L, 0x00000000L,
0x20020000L, 0x00800080L, 0x20800000L, 0x20820080L,
0x00000080L, 0x20000000L, 0x00820000L, 0x00020080L,
0x00820080L, 0x20020080L, 0x20000080L, 0x20800000L,
0x00020000L, 0x00820080L, 0x00800080L, 0x20020000L,
0x20820080L, 0x20000080L, 0x00000000L, 0x00820000L,
0x20000000L, 0x00800000L, 0x20020080L, 0x20800080L,
0x00800000L, 0x00020000L, 0x20820000L, 0x00000080L,
0x00800000L, 0x00020000L, 0x20000080L, 0x20820080L,
0x00020080L, 0x20000000L, 0x00000000L, 0x00820000L,
0x20800080L, 0x20020080L, 0x20020000L, 0x00800080L,
0x20820000L, 0x00000080L, 0x00800080L, 0x20020000L,
0x20820080L, 0x00800000L, 0x20800000L, 0x20000080L,
0x00820000L, 0x00020080L, 0x20020080L, 0x20800000L,
0x00000080L, 0x20820000L, 0x00820080L, 0x00000000L,
0x20000000L, 0x20800080L, 0x00020000L, 0x00820080L,
}};


const DES_LONG des_skb[8][64]={
  {
    /* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
    0x00000000L,0x00000010L,0x20000000L,0x20000010L,
    0x00010000L,0x00010010L,0x20010000L,0x20010010L,
    0x00000800L,0x00000810L,0x20000800L,0x20000810L,
    0x00010800L,0x00010810L,0x20010800L,0x20010810L,
    0x00000020L,0x00000030L,0x20000020L,0x20000030L,
    0x00010020L,0x00010030L,0x20010020L,0x20010030L,
    0x00000820L,0x00000830L,0x20000820L,0x20000830L,
    0x00010820L,0x00010830L,0x20010820L,0x20010830L,
    0x00080000L,0x00080010L,0x20080000L,0x20080010L,
    0x00090000L,0x00090010L,0x20090000L,0x20090010L,
    0x00080800L,0x00080810L,0x20080800L,0x20080810L,
    0x00090800L,0x00090810L,0x20090800L,0x20090810L,
    0x00080020L,0x00080030L,0x20080020L,0x20080030L,
    0x00090020L,0x00090030L,0x20090020L,0x20090030L,
    0x00080820L,0x00080830L,0x20080820L,0x20080830L,
    0x00090820L,0x00090830L,0x20090820L,0x20090830L,
  },{
    /* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
    0x00000000L,0x02000000L,0x00002000L,0x02002000L,
    0x00200000L,0x02200000L,0x00202000L,0x02202000L,
    0x00000004L,0x02000004L,0x00002004L,0x02002004L,
    0x00200004L,0x02200004L,0x00202004L,0x02202004L,
    0x00000400L,0x02000400L,0x00002400L,0x02002400L,
    0x00200400L,0x02200400L,0x00202400L,0x02202400L,
    0x00000404L,0x02000404L,0x00002404L,0x02002404L,
    0x00200404L,0x02200404L,0x00202404L,0x02202404L,
    0x10000000L,0x12000000L,0x10002000L,0x12002000L,
    0x10200000L,0x12200000L,0x10202000L,0x12202000L,
    0x10000004L,0x12000004L,0x10002004L,0x12002004L,
    0x10200004L,0x12200004L,0x10202004L,0x12202004L,
    0x10000400L,0x12000400L,0x10002400L,0x12002400L,
    0x10200400L,0x12200400L,0x10202400L,0x12202400L,
    0x10000404L,0x12000404L,0x10002404L,0x12002404L,
    0x10200404L,0x12200404L,0x10202404L,0x12202404L,
  },{
    /* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
    0x00000000L,0x00000001L,0x00040000L,0x00040001L,
    0x01000000L,0x01000001L,0x01040000L,0x01040001L,
    0x00000002L,0x00000003L,0x00040002L,0x00040003L,
    0x01000002L,0x01000003L,0x01040002L,0x01040003L,
    0x00000200L,0x00000201L,0x00040200L,0x00040201L,
    0x01000200L,0x01000201L,0x01040200L,0x01040201L,
    0x00000202L,0x00000203L,0x00040202L,0x00040203L,
    0x01000202L,0x01000203L,0x01040202L,0x01040203L,
    0x08000000L,0x08000001L,0x08040000L,0x08040001L,
    0x09000000L,0x09000001L,0x09040000L,0x09040001L,
    0x08000002L,0x08000003L,0x08040002L,0x08040003L,
    0x09000002L,0x09000003L,0x09040002L,0x09040003L,
    0x08000200L,0x08000201L,0x08040200L,0x08040201L,
    0x09000200L,0x09000201L,0x09040200L,0x09040201L,
    0x08000202L,0x08000203L,0x08040202L,0x08040203L,
    0x09000202L,0x09000203L,0x09040202L,0x09040203L,
  },{
    /* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
    0x00000000L,0x00100000L,0x00000100L,0x00100100L,
    0x00000008L,0x00100008L,0x00000108L,0x00100108L,
    0x00001000L,0x00101000L,0x00001100L,0x00101100L,
    0x00001008L,0x00101008L,0x00001108L,0x00101108L,
    0x04000000L,0x04100000L,0x04000100L,0x04100100L,
    0x04000008L,0x04100008L,0x04000108L,0x04100108L,
    0x04001000L,0x04101000L,0x04001100L,0x04101100L,
    0x04001008L,0x04101008L,0x04001108L,0x04101108L,
    0x00020000L,0x00120000L,0x00020100L,0x00120100L,
    0x00020008L,0x00120008L,0x00020108L,0x00120108L,
    0x00021000L,0x00121000L,0x00021100L,0x00121100L,
    0x00021008L,0x00121008L,0x00021108L,0x00121108L,
    0x04020000L,0x04120000L,0x04020100L,0x04120100L,
    0x04020008L,0x04120008L,0x04020108L,0x04120108L,
    0x04021000L,0x04121000L,0x04021100L,0x04121100L,
    0x04021008L,0x04121008L,0x04021108L,0x04121108L,
  },{
    /* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
    0x00000000L,0x10000000L,0x00010000L,0x10010000L,
    0x00000004L,0x10000004L,0x00010004L,0x10010004L,
    0x20000000L,0x30000000L,0x20010000L,0x30010000L,
    0x20000004L,0x30000004L,0x20010004L,0x30010004L,
    0x00100000L,0x10100000L,0x00110000L,0x10110000L,
    0x00100004L,0x10100004L,0x00110004L,0x10110004L,
    0x20100000L,0x30100000L,0x20110000L,0x30110000L,
    0x20100004L,0x30100004L,0x20110004L,0x30110004L,
    0x00001000L,0x10001000L,0x00011000L,0x10011000L,
    0x00001004L,0x10001004L,0x00011004L,0x10011004L,
    0x20001000L,0x30001000L,0x20011000L,0x30011000L,
    0x20001004L,0x30001004L,0x20011004L,0x30011004L,
    0x00101000L,0x10101000L,0x00111000L,0x10111000L,
    0x00101004L,0x10101004L,0x00111004L,0x10111004L,
    0x20101000L,0x30101000L,0x20111000L,0x30111000L,
    0x20101004L,0x30101004L,0x20111004L,0x30111004L,
  },{
    /* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
    0x00000000L,0x08000000L,0x00000008L,0x08000008L,
    0x00000400L,0x08000400L,0x00000408L,0x08000408L,
    0x00020000L,0x08020000L,0x00020008L,0x08020008L,
    0x00020400L,0x08020400L,0x00020408L,0x08020408L,
    0x00000001L,0x08000001L,0x00000009L,0x08000009L,
    0x00000401L,0x08000401L,0x00000409L,0x08000409L,
    0x00020001L,0x08020001L,0x00020009L,0x08020009L,
    0x00020401L,0x08020401L,0x00020409L,0x08020409L,
    0x02000000L,0x0A000000L,0x02000008L,0x0A000008L,
    0x02000400L,0x0A000400L,0x02000408L,0x0A000408L,
    0x02020000L,0x0A020000L,0x02020008L,0x0A020008L,
    0x02020400L,0x0A020400L,0x02020408L,0x0A020408L,
    0x02000001L,0x0A000001L,0x02000009L,0x0A000009L,
    0x02000401L,0x0A000401L,0x02000409L,0x0A000409L,
    0x02020001L,0x0A020001L,0x02020009L,0x0A020009L,
    0x02020401L,0x0A020401L,0x02020409L,0x0A020409L,
  },{
    /* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
    0x00000000L,0x00000100L,0x00080000L,0x00080100L,
    0x01000000L,0x01000100L,0x01080000L,0x01080100L,
    0x00000010L,0x00000110L,0x00080010L,0x00080110L,
    0x01000010L,0x01000110L,0x01080010L,0x01080110L,
    0x00200000L,0x00200100L,0x00280000L,0x00280100L,
    0x01200000L,0x01200100L,0x01280000L,0x01280100L,
    0x00200010L,0x00200110L,0x00280010L,0x00280110L,
    0x01200010L,0x01200110L,0x01280010L,0x01280110L,
    0x00000200L,0x00000300L,0x00080200L,0x00080300L,
    0x01000200L,0x01000300L,0x01080200L,0x01080300L,
    0x00000210L,0x00000310L,0x00080210L,0x00080310L,
    0x01000210L,0x01000310L,0x01080210L,0x01080310L,
    0x00200200L,0x00200300L,0x00280200L,0x00280300L,
    0x01200200L,0x01200300L,0x01280200L,0x01280300L,
    0x00200210L,0x00200310L,0x00280210L,0x00280310L,
    0x01200210L,0x01200310L,0x01280210L,0x01280310L,
  },{
    /* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
    0x00000000L,0x04000000L,0x00040000L,0x04040000L,
    0x00000002L,0x04000002L,0x00040002L,0x04040002L,
    0x00002000L,0x04002000L,0x00042000L,0x04042000L,
    0x00002002L,0x04002002L,0x00042002L,0x04042002L,
    0x00000020L,0x04000020L,0x00040020L,0x04040020L,
    0x00000022L,0x04000022L,0x00040022L,0x04040022L,
    0x00002020L,0x04002020L,0x00042020L,0x04042020L,
    0x00002022L,0x04002022L,0x00042022L,0x04042022L,
    0x00000800L,0x04000800L,0x00040800L,0x04040800L,
    0x00000802L,0x04000802L,0x00040802L,0x04040802L,
    0x00002800L,0x04002800L,0x00042800L,0x04042800L,
    0x00002802L,0x04002802L,0x00042802L,0x04042802L,
    0x00000820L,0x04000820L,0x00040820L,0x04040820L,
    0x00000822L,0x04000822L,0x00040822L,0x04040822L,
    0x00002820L,0x04002820L,0x00042820L,0x04042820L,
    0x00002822L,0x04002822L,0x00042822L,0x04042822L,
  }};


/*
 * Description: set DES key schedule, without parity or weakness checks
 *
 * Revision History:
 *  Jan. 18, 2013      Nnoduka Eruchalu     Initial Revision
 */
void DES::set_key(const DES_cblock *key, DES_key_schedule *schedule)
{
  static const int shifts2[16]={0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};
  register DES_LONG c,d,t,s,t2;
  register const unsigned char *in;
  register DES_LONG *k;
  register int i;

  k = &schedule->ks->deslong[0];
  in = &(*key)[0];

  c2l(in,c);
  c2l(in,d);

  /* do PC1 in 47 simple operations :-)
   * Thanks to John Fletcher (john_fletcher@lccmail.ocf.llnl.gov)
   * for the inspiration. :-) */
  PERM_OP (d,c,t,4,0x0f0f0f0fL);
  HPERM_OP(c,t,-2,0xcccc0000L);
  HPERM_OP(d,t,-2,0xcccc0000L);
  PERM_OP (d,c,t,1,0x55555555L);
  PERM_OP (c,d,t,8,0x00ff00ffL);
  PERM_OP (d,c,t,1,0x55555555L);
  d=  (((d&0x000000ffL)<<16L)| (d&0x0000ff00L)     |
         ((d&0x00ff0000L)>>16L)|((c&0xf0000000L)>>4L));
  c&=0x0fffffffL;
  
  for (i=0; i<16; i++)
    {
      if (shifts2[i])
        { c=((c>>2L)|(c<<26L)); d=((d>>2L)|(d<<26L)); }
      else
        { c=((c>>1L)|(c<<27L)); d=((d>>1L)|(d<<27L)); }
      c&=0x0fffffffL;
      d&=0x0fffffffL;
      /* could be a few less shifts but I am to lazy at this
       * point in time to investigate */
      s=  des_skb[0][ (c    )&0x3f                ]|
        des_skb[1][((c>> 6L)&0x03)|((c>> 7L)&0x3c)]|
        des_skb[2][((c>>13L)&0x0f)|((c>>14L)&0x30)]|
        des_skb[3][((c>>20L)&0x01)|((c>>21L)&0x06) |
                   ((c>>22L)&0x38)];
      t=  des_skb[4][ (d    )&0x3f                ]|
        des_skb[5][((d>> 7L)&0x03)|((d>> 8L)&0x3c)]|
        des_skb[6][ (d>>15L)&0x3f                ]|
        des_skb[7][((d>>21L)&0x0f)|((d>>22L)&0x30)];
      
      /* table contained 0213 4657 */
      t2=((t<<16L)|(s&0x0000ffffL))&0xffffffffL;
      *(k++)=ROTATE(t2,30)&0xffffffffL;
      
      t2=((s>>16L)|(t&0xffff0000L));
      *(k++)=ROTATE(t2,26)&0xffffffffL;
    }
}

/*
 * DES_ecb_encrypt
 * Description: The basic DES ecryption routine that encrypts or decrypts a 
 *              single 8-byte DES_cblock in electronic code book (ECB) mode. It 
 *              always transforms the input data pointed to by `input`, into the
 *              output data, pointed to by the `ouput` argument. If the 
 *              `encrypt` argument is non-zero (DES_ENCRYPT), the input
 *              (cleartext) is encrypted in to the output (ciphertext) using the
 *              key_schedule specified by the schedule argument, previously set 
 *              via DES_set_key. If `encrypt is zero (DES_DECRYPT), the input 
 *              (now ciphertext) is decrypted into the output (now cleartext). 
 *              Input and output may overlap.
 *
 * Return:      None 
 *
 * Revision History:
 *   Jan. 06, 2013      Nnoduka Eruchalu     Initial Revision
 */
void DES::ecb_encrypt(const DES_cblock *input, DES_cblock *output,
                      DES_key_schedule *ks, int enc)
{
  register DES_LONG l;
  DES_LONG ll[2];
  const unsigned char *in = &(*input)[0];
  unsigned char *out = &(*output)[0];
  
  c2l(in,l); ll[0]=l;
  c2l(in,l); ll[1]=l;
  encrypt1(ll,ks,enc);
  l=ll[0]; l2c(l,out);
  l=ll[1]; l2c(l,out);
  l=ll[0]=ll[1]=0;
}


/*
 * encrypt1
 * Description: This is the DES encryption function that gets called by just 
 *              about every other DES routine in the library.  You should not 
 *              use this function except to implement 'modes' of DES.  I say 
 *              this because the functions that call this routine do the 
 *              conversion from 'char *' to long, and this needs to be done to 
 *              make sure 'non-aligned' memory access do not occur.  The 
 *              characters are loaded 'little endian'. Data is a pointer to 2 
 *              unsigned long's and ks is the DES_key_schedule to use.  enc, is 
 *              non zero specifies encryption, zero if decryption. 
 *
 * Return:      None 
 *
 * Revision History:
 *   Jan. 06, 2013      Nnoduka Eruchalu     Initial Revision
 */
void DES::encrypt1(DES_LONG *data,DES_key_schedule *ks, int enc)
{
  register DES_LONG l,r,t,u;
  register int i;
  register DES_LONG *s;
  
  r=data[0];
  l=data[1];
  
  IP(r,l);
  /* Things have been modified so that the initial rotate is
   * done outside the loop.  This required the
   * DES_SPtrans values in sp.h to be rotated 1 bit to the right.
   * One perl script later and things have a 5% speed up on a sparc2.
   * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
   * for pointing this out. */
  /* clear the top bits on machines with 8byte longs */
  /* shift left by 2 */
  r=ROTATE(r,29)&0xffffffffL;
  l=ROTATE(l,29)&0xffffffffL;
  
  s=ks->ks->deslong;
  if (enc) {
    for (i=0; i<32; i+=4) {
      D_ENCRYPT(l,r,i+0); /*  1 */
      D_ENCRYPT(r,l,i+2); /*  2 */
    }
  } else {
    for (i=30; i>0; i-=4) {
      D_ENCRYPT(l,r,i-0); /* 16 */
      D_ENCRYPT(r,l,i-2); /* 15 */
    }
  }
  
  /* rotate and clear the top bits on machines with 8byte longs */
  l=ROTATE(l,3)&0xffffffffL;
  r=ROTATE(r,3)&0xffffffffL;
  
  FP(r,l);
  data[0]=l;
  data[1]=r;
  l=r=t=u=0;
}


// ----------------------------------------------------------------------------------------------
// C++ code added by Elmü
// ----------------------------------------------------------------------------------------------

DES::DES()
{
    ms32_BlockSize = 8; // DES always encrypts blocks of 8 byte independent of the key size
    // No need to initialize mk_ks1..3 here because they are assigned in SetKeyData().
}

DES::~DES()
{
}

// DES supports 3 modes:
// Keying option 1:  All three keys are different.                (3K3DES = 3 × 56 = 168 bit key)
// Keying option 2:  K1 and K2 are different, and K3 = K1.        (2K3DES = 2 × 56 = 112 bit key)
// Keying option 3:  All three keys are identical: K1 = K2 = K3.  (DES    = 1 * 56 bit key, obsolete)

// Bit 0 of each byte in the key is not used for encryption. (Only 56 of 64 bit are used)
// Formerly it has been used as parity bit. Desfire uses it to store the 8 bit key version.

// ATTENTION: If you pass 24 byte and K1 == K2 == K3 this is not a 3K3DES key.
// But this may be intention if you want to authenticate with a 3K3DES key and the default key is 24 zeroes (which in reality is simple DES).
// You cannot authenticate with a simple DES key if the card expects a 3K3DES key because the session key will be calculated differently.

bool DES::SetKeyData(const byte* u8_Key, int s32_KeySize, byte u8_Version)
{
    StoreKeyVersion(mu8_Key, u8_Key, s32_KeySize, u8_Version);
  
    DES_cblock* pk_Block = (DES_cblock*)mu8_Key;
    switch (s32_KeySize)
    {
        case 8: // simple DES
            for (int i=0; i<8; i++)
            {  
                // Copy k1 -> k2 (The upper 8 bytes are not used for encryption, but they are required in Desfire::ChangeKey())
                mu8_Key[i+8] = mu8_Key[i];
            }
            set_key(&pk_Block[0], &mk_ks1);
            me_KeyType = DF_KEY_2K3DES;
            break;

        case 16: // 2K3DES
            set_key(&pk_Block[0], &mk_ks1);
            set_key(&pk_Block[1], &mk_ks2);
            me_KeyType = DF_KEY_2K3DES;
            break;

        case 24: // 3K3DES
            set_key(&pk_Block[0], &mk_ks1);
            set_key(&pk_Block[1], &mk_ks2);        
            set_key(&pk_Block[2], &mk_ks3);
            me_KeyType = DF_KEY_3K3DES;
            break;

        default:
            return false;
    }

    ClearIV(); // Fill IV with zeroes
    mu8_Version  = u8_Version;
    ms32_KeySize = s32_KeySize;
    return true;
}

// 1 block = 8 bytes
bool DES::CryptDataBlock(byte u8_Out[8], const byte u8_In[8], DESFireCipher e_Cipher)
{
    switch (ms32_KeySize)
    {
        case 8: // simple DES
            if (e_Cipher == KEY_ENCIPHER)
            {
                ecb_encrypt((DES_cblock*)u8_In, (DES_cblock*)u8_Out, &mk_ks1, DES_ENCRYPT);
            }
            else // KEY_DECIPHER
            {
                ecb_encrypt((DES_cblock*)u8_In, (DES_cblock*)u8_Out, &mk_ks1, DES_DECRYPT);
            }
            return true;

        case 16: // 2K3DES
            if (e_Cipher == KEY_ENCIPHER)
            {
                ecb_encrypt((DES_cblock*)u8_In,  (DES_cblock*)u8_Out, &mk_ks1, DES_ENCRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks2, DES_DECRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks1, DES_ENCRYPT);
            }
            else // KEY_DECIPHER
            {
                ecb_encrypt((DES_cblock*)u8_In,  (DES_cblock*)u8_Out, &mk_ks1, DES_DECRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks2, DES_ENCRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks1, DES_DECRYPT);
            }
            return true;
            
        case 24: // 3K3DES
            if (e_Cipher == KEY_ENCIPHER)
            {
                ecb_encrypt((DES_cblock*)u8_In,  (DES_cblock*)u8_Out, &mk_ks1, DES_ENCRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks2, DES_DECRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks3, DES_ENCRYPT);
            }
            else // KEY_DECIPHER
            {
                ecb_encrypt((DES_cblock*)u8_In,  (DES_cblock*)u8_Out, &mk_ks3, DES_DECRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks2, DES_ENCRYPT);
                ecb_encrypt((DES_cblock*)u8_Out, (DES_cblock*)u8_Out, &mk_ks1, DES_DECRYPT);
            }
            return true;
    }
    return false; // key not set
}

// The 8 bit version number is stored in the parity bit (bit 0) of the first 8 bytes of the key.
// The bit 0 of the key bytes is not used for encryption. (A 64 bit key uses only 56 bit, a 128 bit key uses only 112 bit for encryption)
// s32_KeySize must be 8, 16 or 24
void DES::StoreKeyVersion(byte* u8_KeyOut, const byte* u8_KeyIn, int s32_KeySize, byte u8_Version)
{
    byte u8_Mask = 0x80;
    for (int i=0; i<8; i++)
    {
        byte u8_Parity = (u8_Version & u8_Mask) ? 0x01 : 0x00;
        u8_KeyOut[i] = (u8_KeyIn[i] & 0xFE) | u8_Parity;
        u8_Mask >>= 1;
    }
    
    for (int i=8; i<s32_KeySize; i++)
    {
        // Set Parity bit = 0
        u8_KeyOut[i] = u8_KeyIn[i] & 0xFE;
    }
}


