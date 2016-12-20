/*
* Copyright (C) 2016 Intel Corporation. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
*   * Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*   * Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*   * Neither the name of Intel Corporation nor the names of its
*     contributors may be used to endorse or promote products derived
*     from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#if !defined(_PCP_RIJTBLES_H)
#define _PCP_RIJTBLES_H

#include "owndefs.h"
#include "owncp.h"
#include "pcprij.h"

/*
// GF(256) multiplication operations
*/
#define gf_m2(x)   ((x<<1) ^ (((x>>7) & 1) * WPOLY))
#define gf_m4(x)   ((x<<2) ^ (((x>>6) & 1) * WPOLY) ^ (((x>>6) & 2) * WPOLY))
#define gf_m8(x)   ((x<<3) ^ (((x>>5) & 1) * WPOLY) ^ (((x>>5) & 2) * WPOLY) \
                           ^ (((x>>5) & 4) * WPOLY))
#define gf_m1(x)   ((x))
#define gf_m3(x)   (gf_m2(x) ^ x)
#define gf_m9(x)   (gf_m8(x) ^ x)
#define gf_mB(x)   (gf_m8(x) ^ gf_m2(x) ^ x)
#define gf_mD(x)   (gf_m8(x) ^ gf_m4(x) ^ x)
#define gf_mE(x)   (gf_m8(x) ^ gf_m4(x) ^ gf_m2(x))

/*
// The following particular transformations
// are used for create Encryption Tables
*/
#define fwd_t0(x) BYTES_TO_WORD(gf_m2(x), gf_m1(x), gf_m1(x), gf_m3(x))
#define fwd_t1(x) BYTES_TO_WORD(gf_m3(x), gf_m2(x), gf_m1(x), gf_m1(x))
#define fwd_t2(x) BYTES_TO_WORD(gf_m1(x), gf_m3(x), gf_m2(x), gf_m1(x))
#define fwd_t3(x) BYTES_TO_WORD(gf_m1(x), gf_m1(x), gf_m3(x), gf_m2(x))

/*
// The following particular transformations
// are used for create Decryption Tables
*/
#define inv_t0(x) BYTES_TO_WORD(gf_mE(x), gf_m9(x), gf_mD(x), gf_mB(x))
#define inv_t1(x) BYTES_TO_WORD(gf_mB(x), gf_mE(x), gf_m9(x), gf_mD(x))
#define inv_t2(x) BYTES_TO_WORD(gf_mD(x), gf_mB(x), gf_mE(x), gf_m9(x))
#define inv_t3(x) BYTES_TO_WORD(gf_m9(x), gf_mD(x), gf_mB(x), gf_mE(x))

#define exp_b3(x) BYTES_TO_WORD(0, 0, 0, (x))
#define exp_b2(x) BYTES_TO_WORD(0, 0, (x),0)
#define exp_b1(x) BYTES_TO_WORD(0, (x),0, 0)
#define exp_b0(x) BYTES_TO_WORD((x),0, 0, 0)

/*
// The following particular transformations
// are used for create pure Encryption/Decryption Sboxes
*/
#define none_t(x) (x)


/*
// Just sequence of byte, beginning 0x00 upto 0xff
// (be parametrized by any transformation 't')
*/
#define LINE(t) \
   t(0x00), t(0x01), t(0x02), t(0x03), t(0x04), t(0x05), t(0x06), t(0x07),\
   t(0x08), t(0x09), t(0x0a), t(0x0b), t(0x0c), t(0x0d), t(0x0e), t(0x0f),\
   t(0x10), t(0x11), t(0x12), t(0x13), t(0x14), t(0x15), t(0x16), t(0x17),\
   t(0x18), t(0x19), t(0x1a), t(0x1b), t(0x1c), t(0x1d), t(0x1e), t(0x1f),\
   t(0x20), t(0x21), t(0x22), t(0x23), t(0x24), t(0x25), t(0x26), t(0x27),\
   t(0x28), t(0x29), t(0x2a), t(0x2b), t(0x2c), t(0x2d), t(0x2e), t(0x2f),\
   t(0x30), t(0x31), t(0x32), t(0x33), t(0x34), t(0x35), t(0x36), t(0x37),\
   t(0x38), t(0x39), t(0x3a), t(0x3b), t(0x3c), t(0x3d), t(0x3e), t(0x3f),\
   t(0x40), t(0x41), t(0x42), t(0x43), t(0x44), t(0x45), t(0x46), t(0x47),\
   t(0x48), t(0x49), t(0x4a), t(0x4b), t(0x4c), t(0x4d), t(0x4e), t(0x4f),\
   t(0x50), t(0x51), t(0x52), t(0x53), t(0x54), t(0x55), t(0x56), t(0x57),\
   t(0x58), t(0x59), t(0x5a), t(0x5b), t(0x5c), t(0x5d), t(0x5e), t(0x5f),\
   t(0x60), t(0x61), t(0x62), t(0x63), t(0x64), t(0x65), t(0x66), t(0x67),\
   t(0x68), t(0x69), t(0x6a), t(0x6b), t(0x6c), t(0x6d), t(0x6e), t(0x6f),\
   t(0x70), t(0x71), t(0x72), t(0x73), t(0x74), t(0x75), t(0x76), t(0x77),\
   t(0x78), t(0x79), t(0x7a), t(0x7b), t(0x7c), t(0x7d), t(0x7e), t(0x7f),\
   t(0x80), t(0x81), t(0x82), t(0x83), t(0x84), t(0x85), t(0x86), t(0x87),\
   t(0x88), t(0x89), t(0x8a), t(0x8b), t(0x8c), t(0x8d), t(0x8e), t(0x8f),\
   t(0x90), t(0x91), t(0x92), t(0x93), t(0x94), t(0x95), t(0x96), t(0x97),\
   t(0x98), t(0x99), t(0x9a), t(0x9b), t(0x9c), t(0x9d), t(0x9e), t(0x9f),\
   t(0xa0), t(0xa1), t(0xa2), t(0xa3), t(0xa4), t(0xa5), t(0xa6), t(0xa7),\
   t(0xa8), t(0xa9), t(0xaa), t(0xab), t(0xac), t(0xad), t(0xae), t(0xaf),\
   t(0xb0), t(0xb1), t(0xb2), t(0xb3), t(0xb4), t(0xb5), t(0xb6), t(0xb7),\
   t(0xb8), t(0xb9), t(0xba), t(0xbb), t(0xbc), t(0xbd), t(0xbe), t(0xbf),\
   t(0xc0), t(0xc1), t(0xc2), t(0xc3), t(0xc4), t(0xc5), t(0xc6), t(0xc7),\
   t(0xc8), t(0xc9), t(0xca), t(0xcb), t(0xcc), t(0xcd), t(0xce), t(0xcf),\
   t(0xd0), t(0xd1), t(0xd2), t(0xd3), t(0xd4), t(0xd5), t(0xd6), t(0xd7),\
   t(0xd8), t(0xd9), t(0xda), t(0xdb), t(0xdc), t(0xdd), t(0xde), t(0xdf),\
   t(0xe0), t(0xe1), t(0xe2), t(0xe3), t(0xe4), t(0xe5), t(0xe6), t(0xe7),\
   t(0xe8), t(0xe9), t(0xea), t(0xeb), t(0xec), t(0xed), t(0xee), t(0xef),\
   t(0xf0), t(0xf1), t(0xf2), t(0xf3), t(0xf4), t(0xf5), t(0xf6), t(0xf7),\
   t(0xf8), t(0xf9), t(0xfa), t(0xfb), t(0xfc), t(0xfd), t(0xfe), t(0xff)

/*
// Encrypt/Decrypt S-box data
// (be parametrized by any transformation 't')
*/
#define ENC_SBOX(t) \
   t(0x63), t(0x7c), t(0x77), t(0x7b), t(0xf2), t(0x6b), t(0x6f), t(0xc5),\
   t(0x30), t(0x01), t(0x67), t(0x2b), t(0xfe), t(0xd7), t(0xab), t(0x76),\
   t(0xca), t(0x82), t(0xc9), t(0x7d), t(0xfa), t(0x59), t(0x47), t(0xf0),\
   t(0xad), t(0xd4), t(0xa2), t(0xaf), t(0x9c), t(0xa4), t(0x72), t(0xc0),\
   t(0xb7), t(0xfd), t(0x93), t(0x26), t(0x36), t(0x3f), t(0xf7), t(0xcc),\
   t(0x34), t(0xa5), t(0xe5), t(0xf1), t(0x71), t(0xd8), t(0x31), t(0x15),\
   t(0x04), t(0xc7), t(0x23), t(0xc3), t(0x18), t(0x96), t(0x05), t(0x9a),\
   t(0x07), t(0x12), t(0x80), t(0xe2), t(0xeb), t(0x27), t(0xb2), t(0x75),\
   t(0x09), t(0x83), t(0x2c), t(0x1a), t(0x1b), t(0x6e), t(0x5a), t(0xa0),\
   t(0x52), t(0x3b), t(0xd6), t(0xb3), t(0x29), t(0xe3), t(0x2f), t(0x84),\
   t(0x53), t(0xd1), t(0x00), t(0xed), t(0x20), t(0xfc), t(0xb1), t(0x5b),\
   t(0x6a), t(0xcb), t(0xbe), t(0x39), t(0x4a), t(0x4c), t(0x58), t(0xcf),\
   t(0xd0), t(0xef), t(0xaa), t(0xfb), t(0x43), t(0x4d), t(0x33), t(0x85),\
   t(0x45), t(0xf9), t(0x02), t(0x7f), t(0x50), t(0x3c), t(0x9f), t(0xa8),\
   t(0x51), t(0xa3), t(0x40), t(0x8f), t(0x92), t(0x9d), t(0x38), t(0xf5),\
   t(0xbc), t(0xb6), t(0xda), t(0x21), t(0x10), t(0xff), t(0xf3), t(0xd2),\
   t(0xcd), t(0x0c), t(0x13), t(0xec), t(0x5f), t(0x97), t(0x44), t(0x17),\
   t(0xc4), t(0xa7), t(0x7e), t(0x3d), t(0x64), t(0x5d), t(0x19), t(0x73),\
   t(0x60), t(0x81), t(0x4f), t(0xdc), t(0x22), t(0x2a), t(0x90), t(0x88),\
   t(0x46), t(0xee), t(0xb8), t(0x14), t(0xde), t(0x5e), t(0x0b), t(0xdb),\
   t(0xe0), t(0x32), t(0x3a), t(0x0a), t(0x49), t(0x06), t(0x24), t(0x5c),\
   t(0xc2), t(0xd3), t(0xac), t(0x62), t(0x91), t(0x95), t(0xe4), t(0x79),\
   t(0xe7), t(0xc8), t(0x37), t(0x6d), t(0x8d), t(0xd5), t(0x4e), t(0xa9),\
   t(0x6c), t(0x56), t(0xf4), t(0xea), t(0x65), t(0x7a), t(0xae), t(0x08),\
   t(0xba), t(0x78), t(0x25), t(0x2e), t(0x1c), t(0xa6), t(0xb4), t(0xc6),\
   t(0xe8), t(0xdd), t(0x74), t(0x1f), t(0x4b), t(0xbd), t(0x8b), t(0x8a),\
   t(0x70), t(0x3e), t(0xb5), t(0x66), t(0x48), t(0x03), t(0xf6), t(0x0e),\
   t(0x61), t(0x35), t(0x57), t(0xb9), t(0x86), t(0xc1), t(0x1d), t(0x9e),\
   t(0xe1), t(0xf8), t(0x98), t(0x11), t(0x69), t(0xd9), t(0x8e), t(0x94),\
   t(0x9b), t(0x1e), t(0x87), t(0xe9), t(0xce), t(0x55), t(0x28), t(0xdf),\
   t(0x8c), t(0xa1), t(0x89), t(0x0d), t(0xbf), t(0xe6), t(0x42), t(0x68),\
   t(0x41), t(0x99), t(0x2d), t(0x0f), t(0xb0), t(0x54), t(0xbb), t(0x16)

#define DEC_SBOX(t) \
   t(0x52), t(0x09), t(0x6a), t(0xd5), t(0x30), t(0x36), t(0xa5), t(0x38),\
   t(0xbf), t(0x40), t(0xa3), t(0x9e), t(0x81), t(0xf3), t(0xd7), t(0xfb),\
   t(0x7c), t(0xe3), t(0x39), t(0x82), t(0x9b), t(0x2f), t(0xff), t(0x87),\
   t(0x34), t(0x8e), t(0x43), t(0x44), t(0xc4), t(0xde), t(0xe9), t(0xcb),\
   t(0x54), t(0x7b), t(0x94), t(0x32), t(0xa6), t(0xc2), t(0x23), t(0x3d),\
   t(0xee), t(0x4c), t(0x95), t(0x0b), t(0x42), t(0xfa), t(0xc3), t(0x4e),\
   t(0x08), t(0x2e), t(0xa1), t(0x66), t(0x28), t(0xd9), t(0x24), t(0xb2),\
   t(0x76), t(0x5b), t(0xa2), t(0x49), t(0x6d), t(0x8b), t(0xd1), t(0x25),\
   t(0x72), t(0xf8), t(0xf6), t(0x64), t(0x86), t(0x68), t(0x98), t(0x16),\
   t(0xd4), t(0xa4), t(0x5c), t(0xcc), t(0x5d), t(0x65), t(0xb6), t(0x92),\
   t(0x6c), t(0x70), t(0x48), t(0x50), t(0xfd), t(0xed), t(0xb9), t(0xda),\
   t(0x5e), t(0x15), t(0x46), t(0x57), t(0xa7), t(0x8d), t(0x9d), t(0x84),\
   t(0x90), t(0xd8), t(0xab), t(0x00), t(0x8c), t(0xbc), t(0xd3), t(0x0a),\
   t(0xf7), t(0xe4), t(0x58), t(0x05), t(0xb8), t(0xb3), t(0x45), t(0x06),\
   t(0xd0), t(0x2c), t(0x1e), t(0x8f), t(0xca), t(0x3f), t(0x0f), t(0x02),\
   t(0xc1), t(0xaf), t(0xbd), t(0x03), t(0x01), t(0x13), t(0x8a), t(0x6b),\
   t(0x3a), t(0x91), t(0x11), t(0x41), t(0x4f), t(0x67), t(0xdc), t(0xea),\
   t(0x97), t(0xf2), t(0xcf), t(0xce), t(0xf0), t(0xb4), t(0xe6), t(0x73),\
   t(0x96), t(0xac), t(0x74), t(0x22), t(0xe7), t(0xad), t(0x35), t(0x85),\
   t(0xe2), t(0xf9), t(0x37), t(0xe8), t(0x1c), t(0x75), t(0xdf), t(0x6e),\
   t(0x47), t(0xf1), t(0x1a), t(0x71), t(0x1d), t(0x29), t(0xc5), t(0x89),\
   t(0x6f), t(0xb7), t(0x62), t(0x0e), t(0xaa), t(0x18), t(0xbe), t(0x1b),\
   t(0xfc), t(0x56), t(0x3e), t(0x4b), t(0xc6), t(0xd2), t(0x79), t(0x20),\
   t(0x9a), t(0xdb), t(0xc0), t(0xfe), t(0x78), t(0xcd), t(0x5a), t(0xf4),\
   t(0x1f), t(0xdd), t(0xa8), t(0x33), t(0x88), t(0x07), t(0xc7), t(0x31),\
   t(0xb1), t(0x12), t(0x10), t(0x59), t(0x27), t(0x80), t(0xec), t(0x5f),\
   t(0x60), t(0x51), t(0x7f), t(0xa9), t(0x19), t(0xb5), t(0x4a), t(0x0d),\
   t(0x2d), t(0xe5), t(0x7a), t(0x9f), t(0x93), t(0xc9), t(0x9c), t(0xef),\
   t(0xa0), t(0xe0), t(0x3b), t(0x4d), t(0xae), t(0x2a), t(0xf5), t(0xb0),\
   t(0xc8), t(0xeb), t(0xbb), t(0x3c), t(0x83), t(0x53), t(0x99), t(0x61),\
   t(0x17), t(0x2b), t(0x04), t(0x7e), t(0xba), t(0x77), t(0xd6), t(0x26),\
   t(0xe1), t(0x69), t(0x14), t(0x63), t(0x55), t(0x21), t(0x0c), t(0x7d),

/*
// Internal cipher tables
*/
extern const __ALIGN64 Ipp8u RijEncSbox[256];    /* pure encryption S-box */
extern const __ALIGN64 Ipp8u RijDecSbox[256];    /* pure decryption S-box */

#endif /* _PCP_RIJTBLES_H */
