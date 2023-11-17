/* AES-256 - CBC MAC */

/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
 /*
  * Copyright (c) 2010 Network Security Lab, University of Washington, Seattle.
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation;
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  *
  * Author: Sidharth Nabar <snabar@uw.edu>, He Wu <mdzz@u.washington.edu>
  */
  
 #include <iostream>
 #include <fstream>
 #include <vector>
 #include <string>
 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/config-store-module.h"
 #include "ns3/energy-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/yans-wifi-helper.h"
 #include "ns3/wifi-radio-energy-model-helper.h"

 #include "ns3/point-to-point-module.h"
 #include "ns3/tag.h"
 #include "ns3/packet.h"
 #include "ns3/string.h"
 #include <sys/time.h>
 #include <unistd.h>
 #include <chrono>

  
 using namespace ns3;
 using namespace std::chrono;
  
 NS_LOG_COMPONENT_DEFINE ("EnergyExample");


   ///// Start clock
   auto start = high_resolution_clock::now();
   /////


///// AES-256 authentication

#include <stdio.h>
#include <stdint.h>

#define AES_BLOCK_SIZE      16
#define AES_ROUNDS          14  // 10, 12
#define AES_ROUND_KEY_SIZE  240 // AES-256 has 12 rounds, and there is a AddRoundKey before first round. (14+1)x16=240.

/**
 * @purpose:            Key schedule for AES-128
 * @par[in]key:         16 bytes of master keys
 * @par[out]roundkeys:  176 bytes of round keys
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);

/**
 * @purpose:            Encryption. The length of plain and cipher should be one block (16 bytes).
 *                      The plaintext and ciphertext may point to the same memory
 * @par[in]roundkeys:   round keys
 * @par[in]plaintext:   plain text
 * @par[out]ciphertext: cipher text
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @purpose:            Decryption. The length of plain and cipher should be one block (16 bytes).
 *                      The ciphertext and plaintext may point to the same memory
 * @par[in]roundkeys:   round keys
 * @par[in]ciphertext:  cipher text
 * @par[out]plaintext:  plain text
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);


/********************************/

/*
 * round constants
 */
static uint8_t RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Sbox
 */
static uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/*
 * Inverse Sboxs
 */
static uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
static inline uint8_t mul2(uint8_t a) {
    return (a&0x80) ? ((a<<1)^0x1b) : (a<<1);
}

/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
static void shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}

/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}

void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys) {

    uint8_t temp[4];
    uint8_t *last4bytes; // point to the last 4 bytes of one round
    uint8_t *lastround;
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys-4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
        temp[0] = SBOX[*last4bytes++];
        temp[1] = SBOX[*last4bytes++];
        temp[2] = SBOX[*last4bytes++];
        temp[0] ^= RC[i];
        lastround = roundkeys-16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}

void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext) {

    uint8_t tmp[16], t;
    uint8_t i, j;

    // first AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(ciphertext+i) = *(plaintext+i) ^ *roundkeys++;
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp+i) = SBOX[*(ciphertext+i)];
        }
        shift_rows(tmp);
        /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4)  {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            ciphertext[i]   = mul2(tmp[i]   ^ tmp[i+1]) ^ tmp[i]   ^ t;
            ciphertext[i+1] = mul2(tmp[i+1] ^ tmp[i+2]) ^ tmp[i+1] ^ t;
            ciphertext[i+2] = mul2(tmp[i+2] ^ tmp[i+3]) ^ tmp[i+2] ^ t;
            ciphertext[i+3] = mul2(tmp[i+3] ^ tmp[i]  ) ^ tmp[i+3] ^ t;
        }

        // AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            *(ciphertext+i) ^= *roundkeys++;
        }

    }
    
    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext+i) = SBOX[*(ciphertext+i)];
    }
    shift_rows(ciphertext);
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(ciphertext+i) ^= *roundkeys++;
    }

}

void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext) {

    uint8_t tmp[16];
    uint8_t t, u, v;
    uint8_t i, j;

    roundkeys += 160;

    // first round
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(plaintext+i) = *(ciphertext+i) ^ *(roundkeys+i);
    }
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext+i) = INV_SBOX[*(plaintext+i)];
    }

    for (j = 1; j < AES_ROUNDS; ++j) {
        
        // Inverse AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            *(tmp+i) = *(plaintext+i) ^ *(roundkeys+i);
        }
        
        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4) {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            plaintext[i]   = t ^ tmp[i]   ^ mul2(tmp[i]   ^ tmp[i+1]);
            plaintext[i+1] = t ^ tmp[i+1] ^ mul2(tmp[i+1] ^ tmp[i+2]);
            plaintext[i+2] = t ^ tmp[i+2] ^ mul2(tmp[i+2] ^ tmp[i+3]);
            plaintext[i+3] = t ^ tmp[i+3] ^ mul2(tmp[i+3] ^ tmp[i]);
            u = mul2(mul2(tmp[i]   ^ tmp[i+2]));
            v = mul2(mul2(tmp[i+1] ^ tmp[i+3]));
            t = mul2(u ^ v);
            plaintext[i]   ^= t ^ u;
            plaintext[i+1] ^= t ^ v;
            plaintext[i+2] ^= t ^ u;
            plaintext[i+3] ^= t ^ v;
        }
        
        // Inverse ShiftRows
        inv_shift_rows(plaintext);
        
        // Inverse SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(plaintext+i) = INV_SBOX[*(plaintext+i)];
        }

        roundkeys -= 32;

    }

    // last AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(plaintext+i) ^= *(roundkeys+i);
    }

}
///// end AES algorithm


///// Calculate memory usage (in kB)
void process_mem_usage(double& vm_usage, double& resident_set)
{
    vm_usage     = 0.0;
    resident_set = 0.0;

    // the two fields we want
    unsigned long vsize;
    long rss;
    {
        std::string ignore;
        std::ifstream ifs("/proc/self/stat", std::ios_base::in);
        ifs >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
                >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
                >> ignore >> ignore >> vsize >> rss;
    }

    long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    vm_usage = vsize / 1024.0;
    resident_set = rss * page_size_kb;
}
/////

/*
///// Begin add header
 class YHeader : public Header
 {
 public:
   YHeader ();
   virtual ~YHeader();

   // must be implemented to become a valid new header.
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (Buffer::Iterator start) const;
   virtual uint32_t Deserialize (Buffer::Iterator start);
   virtual void Print (std::ostream &os) const;
   //void SetSize (uint64_t size);

   // allow protocol-specific access to the header data.
   void SetData (uint32_t data);
   uint32_t GetData (void) const;
 private:
   uint32_t m_data;
   //uint64_t m_size {8};
 };

 YHeader::YHeader () {}
 YHeader::~YHeader() {}

 TypeId
 YHeader::GetTypeId (void)
 {
   static TypeId tid = TypeId ("YHeader")
     .SetParent<Header> ()
     .AddConstructor<YHeader> ()
   ;
   return tid;
 }

 TypeId
 YHeader::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 YHeader::GetSerializedSize (void) const
 {
   return 6;
 }

 void 
 YHeader::Serialize (Buffer::Iterator start) const
 {
   // The 2 byte-constant
   start.WriteU8 (0xfe);
   start.WriteU8 (0xef);
   // The data.
   start.WriteHtonU32 (m_data);
 }

 uint32_t 
 YHeader::Deserialize (Buffer::Iterator start)
 {
   uint8_t tmp;
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xfe);
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xef);
   m_data = start.ReadNtohU32 ();
   return 6; // the number of bytes consumed.
 }

 void 
 YHeader::Print (std::ostream &os) const
 {
   os << "data=" << m_data;
 }

 void 
 YHeader::SetData (uint32_t data)
 {
   m_data = data;
 }

 uint32_t
 YHeader::GetData (void) const
 {
   return m_data;
 }
///// End add header
*/

/*
///// Begin add trailer
 class ZTrailer : public Trailer
 {
 public:
   ZTrailer ();
   virtual ~ZTrailer();

   // must be implemented to become a valid new trailer.
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (Buffer::Iterator start) const;
   virtual uint32_t Deserialize (Buffer::Iterator start);
   virtual void Print (std::ostream &os) const;

   // allow protocol-specific access to the trailer data.
   void SetData (uint32_t data);
   uint32_t GetData (void) const;
 private:
   uint32_t m_data;
 };

 //virtual ZTrailer();
 ZTrailer::ZTrailer () {}
 //virtual ~ZTrailer();
 ZTrailer::~ZTrailer() {}

 TypeId
 ZTrailer::GetTypeId (void)
 {
   static TypeId tid = TypeId ("ZTrailer")
     .SetParent<Trailer> ()
     .AddConstructor<ZTrailer> ()
   ;
   return tid;
 }

 TypeId
 ZTrailer::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 ZTrailer::GetSerializedSize (void) const
 {
   return 6;
 }

 void 
 ZTrailer::Serialize (Buffer::Iterator start) const
 {
   // The 2 byte-constant
   start.WriteU8 (0xfe);
   start.WriteU8 (0xef);
   // The data.
   start.WriteHtonU32 (m_data);
 }

 uint32_t 
 ZTrailer::Deserialize (Buffer::Iterator start)
 {
   uint8_t tmp;
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xfe);
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xef);
   m_data = start.ReadNtohU32 ();
   return 6; // the number of bytes consumed.
 }

 void 
 ZTrailer::Print (std::ostream &os) const
 {
   os << "data=" << m_data;
 }

 void 
 ZTrailer::SetData (uint32_t data)
 {
   m_data = data;
 }

 uint32_t
 ZTrailer::GetData (void) const
 {
   return m_data;
 }
///// End add trailer
*/


///// Begin add tag
 class MyTag : public Tag
 {
 public:
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (TagBuffer i) const;
   virtual void Deserialize (TagBuffer i);
   virtual void Print (std::ostream &os) const;
  
   // these are our accessors to our tag structure
   void SetSimpleValue (uint8_t value);
   uint8_t GetSimpleValue (void) const;
 private:
   uint8_t m_simpleValue;  
 };

 //MyTag::MyTag () {}
 //MyTag::~MyTag() {}

 TypeId 
 MyTag::GetTypeId (void)
 {
   static TypeId tid = TypeId ("ns3::MyTag")
     .SetParent<Tag> ()
     .AddConstructor<MyTag> ()
     .AddAttribute ("SimpleValue",
                    "A simple value",
                    EmptyAttributeValue (),
                    MakeUintegerAccessor (&MyTag::GetSimpleValue),
                    MakeUintegerChecker<uint8_t> ())
   ;
   return tid;
 }

 TypeId 
 MyTag::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 MyTag::GetSerializedSize (void) const
 {
   return 1;
 }

 void 
 MyTag::Serialize (TagBuffer i) const
 {
   i.WriteU8 (m_simpleValue);
 }

 void 
 MyTag::Deserialize (TagBuffer i)
 {
   m_simpleValue = i.ReadU8 ();
 }

 void 
 MyTag::Print (std::ostream &os) const
 {
   os << "v=" << (uint32_t)m_simpleValue;
 }

 void 
 MyTag::SetSimpleValue (uint8_t value)
 {
   m_simpleValue = value;
 }

 uint8_t 
 MyTag::GetSimpleValue (void) const
 {
   return m_simpleValue;
 }
///// End add tag


 static inline std::string
 PrintReceivedPacket (Address& from)
 {
   InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (from);
  
   std::ostringstream oss;
   oss << "--\nReceived one packet! Socket: " << iaddr.GetIpv4 ()
       << " port: " << iaddr.GetPort ()
       << " at time = " << Simulator::Now ().GetSeconds ()
       << "\n--";
  
   return oss.str ();
 }
  
 void
 ReceivePacket (Ptr<Socket> socket)
 {
   Ptr<Packet> packet;
   Address from;
   while ((packet = socket->RecvFrom (from)))
     {
       if (packet->GetSize () > 0)
         {
             NS_LOG_UNCOND (PrintReceivedPacket (from));
         }
     }
 }



 //#include <string.h>
 //char* a = strdup("hello");
 //uint8_t a[1] = {1};
 //uint8_t header[2] = {1,2};
 //uint8_t sender_message;
 //uint8_t sender_hash;


 static void
 GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize, Ptr<Node> n,
                  uint32_t pktCount, Time pktInterval)
 {
   while (pktCount > 0)
     {
       Ptr<Packet> packet = Create<Packet> (pktSize); //message packet
       //uint8_t *buffer = new uint8_t (packet->GetSize ()); //copy message from message packet
       //sender_message = packet->CopyData (buffer, packet->GetSize ());

       //Ptr<Packet> packet1 = Create<Packet> (3); //hash packet
       //uint8_t *buffer1 = new uint8_t (packet1->GetSize ()); //copy hash form hash packet
       //sender_hash = packet1->CopyData (buffer1, packet1->GetSize ());

       //packet->AddAtEnd (packet1);

       // add tag (to number the packets) - Size of tag = 20bytes
       MyTag tag;
       tag.SetSimpleValue (0x56);
       packet->AddPacketTag (tag);

       // add header (hash of message) - Size of header = 8bytes
       //YHeader yHeader;
       //yHeader.SetData (0xffffff);
       //packet->AddHeader (yHeader);

/*
       // add trailer - Size of trailer = 8bytes
       ZTrailer zTrailer;
       zTrailer.SetData (0xdeadbeaf);
       packet->AddTrailer (zTrailer);
*/

       socket->Send (packet);
       //socket->Send (Create<Packet> (pktSize)); // send packete with anonymous data
       //socket->Send (Create<Packet> (reinterpret_cast<const uint8_t*> (a), 5)); // send string
       //socket->Send (Create<Packet> (a, 3)); // send array
       Simulator::Schedule (pktInterval, &GenerateTraffic, socket, pktSize, n,
                            pktCount - 1, pktInterval);
       pktCount = pktCount - 1; 
     }
   //else
   //  {
   //    socket->Close ();
   //  }
 }
  
 void
 RemainingEnergy (double oldValue, double remainingEnergy)
 {
   NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                  << "s Current remaining energy = " << remainingEnergy << "J");
 }
  
 void
 TotalEnergy (double oldValue, double totalEnergy)
 {
   NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                  << "s Total energy consumed by radio = " << totalEnergy << "J");
 }
  
 int
 main (int argc, char *argv[])
 {
//
 	uint8_t ii, r;

	/* 128 bit key */
	uint8_t key[] = {
		0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 
		0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 

	};

	uint8_t plaintext[] = {
		//0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		//0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};

 
	uint8_t ciphertext[AES_BLOCK_SIZE];

	const uint8_t const_cipher[AES_BLOCK_SIZE] = {
		//0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
		//0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9,
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
	};
	
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];

	printf("\n--------------------------------------------------------\n");
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", plaintext[ii]);
	}
	printf("\n\n");	

	// key schedule
	aes_key_schedule_128(key, roundkeys);
	printf("Round Keys:\n");
	for ( r = 0; r <= AES_ROUNDS; r++ ) {
		for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
			printf("%2x ", roundkeys[r*AES_BLOCK_SIZE+ii]);
		}
		printf("\n");
	}
	printf("\n");

	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }

///////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }


////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }

////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }

/////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }

///////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }


////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }

////////
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	printf("Cipher text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != const_cipher[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		printf("%2x ", ciphertext[ii]);
	}
	for (ii = 0; ii < AES_BLOCK_SIZE; ii++) {
		if ( ciphertext[ii] != plaintext[ii] ) { break; }
	}
	if ( AES_BLOCK_SIZE != ii ) { printf("\nDECRYPT WRONG\n\n"); }
	else { printf("\nDECRYPT CORRECT\n\n"); }



   /*
   LogComponentEnable ("EnergySource", LOG_LEVEL_DEBUG);
   LogComponentEnable ("BasicEnergySource", LOG_LEVEL_DEBUG);
   LogComponentEnable ("DeviceEnergyModel", LOG_LEVEL_DEBUG);
   LogComponentEnable ("WifiRadioEnergyModel", LOG_LEVEL_DEBUG);
    */
  
   LogComponentEnable ("EnergyExample", LogLevel (LOG_PREFIX_TIME | LOG_PREFIX_NODE | LOG_LEVEL_INFO));
  
   std::string phyMode ("DsssRate1Mbps");
   double Prss = -80;            // dBm
   uint32_t PpacketSize = 96;   // bytes - packet size = 2 to 125B(uplink) an 2 to 85B(downlink)
   bool verbose = false;

   std::string dataRate = "180kbps";
  
   // simulation parameters
   uint32_t numPackets = 8;  // number of packets to send
   double interval = 1;          // seconds
   double startTime = 0.0;       // seconds
   double distanceToRx = 100.0;  // meters

   /*
    * This is a magic number used to set the transmit power, based on other
    * configuration.
    */
   //double offset = 81;
  
   CommandLine cmd (__FILE__);
   cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
   cmd.AddValue ("Prss", "Intended primary RSS (dBm)", Prss);
   cmd.AddValue ("PpacketSize", "size of application packet sent", PpacketSize);
   cmd.AddValue ("numPackets", "Total number of packets to send", numPackets);
   cmd.AddValue ("startTime", "Simulation start time", startTime);
   cmd.AddValue ("distanceToRx", "X-Axis distance between nodes", distanceToRx);
   cmd.AddValue ("verbose", "Turn on all device log components", verbose);
   cmd.Parse (argc, argv);
  
   // Convert to time object
   Time interPacketInterval = Seconds (interval);
  
   // disable fragmentation for frames below 8 bytes
   Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold",
                       StringValue ("128"));
   // turn off RTS/CTS for frames below 8 bytes
   Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold",
                       StringValue ("128"));
   // Fix non-unicast data rate to be the same as that of unicast
   Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                       StringValue (phyMode));
  
   NodeContainer c;
   c.Create (2);     // create 2 nodes
   NodeContainer networkNodes;
   networkNodes.Add (c.Get (0));
   networkNodes.Add (c.Get (1));

   PointToPointHelper p2p;
   p2p.SetDeviceAttribute ("DataRate", StringValue ("180kbps"));
   p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

   NetDeviceContainer p2pDevices;
   p2pDevices = p2p.Install (c);

  
   // The below set of helpers will help us to put together the wifi NICs we want
   WifiHelper wifi;
   if (verbose)
     {
       wifi.EnableLogComponents ();
     }
   wifi.SetStandard (WIFI_STANDARD_80211b);
  
   /***************************************************************************/
   //YansWifiPhyHelper wifiPhy;
   YansWifiPhyHelper wifiPhy = YansWifiPhyHelper ();
   wifiPhy.Set ("RxGain", DoubleValue (40));
   wifiPhy.Set ("TxGain", DoubleValue (70));
   //wifiPhy.Set ("TxGain", DoubleValue (offset + Prss));
   //wifiPhy.Set ("CcaMode1Threshold", DoubleValue (0.0));
  
   YansWifiChannelHelper wifiChannel;
   wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
   wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
   
   // create wifi channel
   Ptr<YansWifiChannel> wifiChannelPtr = wifiChannel.Create ();
   wifiPhy.SetChannel (wifiChannelPtr);
  
   // Add a MAC and disable rate control
   WifiMacHelper wifiMac;
   wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode",
                                 StringValue (phyMode), "ControlMode",
                                 StringValue (phyMode));
   // Set it to ad-hoc mode
   wifiMac.SetType ("ns3::AdhocWifiMac");
  
   NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, networkNodes);
  
   MobilityHelper mobility;
   Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
   positionAlloc->Add (Vector (0.0, 0.0, 0.0));
   positionAlloc->Add (Vector (2 * distanceToRx, 0.0, 0.0));
   mobility.SetPositionAllocator (positionAlloc);
   mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
   mobility.Install (c);
  
   /***************************************************************************/
   /* energy source */
   BasicEnergySourceHelper basicSourceHelper;
   // configure energy source
   basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (3.6)); //https://tech-journal.semtech.com/analyzing-nb-iot-and-lorawan-sensor-battery-life - battery is 1000-2000mAh, volt is 3.6V

   // install source
   EnergySourceContainer sources = basicSourceHelper.Install (c);
   /* device energy model */
   WifiRadioEnergyModelHelper radioEnergyHelper;
   // configure radio energy model
   radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0000217)); //https://waviot.com/catalog/electric-meters/waviot-single-phase-electricity-meter/ - 5mW, 230V
   //radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.0000217));
   // install device model
   DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (devices, sources);
   /***************************************************************************/
  
   InternetStackHelper internet;
   internet.Install (networkNodes);
  
   Ipv4AddressHelper ipv4;
   NS_LOG_INFO ("Assign IP Addresses.");
   ipv4.SetBase ("10.1.1.0", "255.255.255.0");
   Ipv4InterfaceContainer i = ipv4.Assign (devices);
  
   TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
   Ptr<Socket> recvSink = Socket::CreateSocket (networkNodes.Get (1), tid);  // node 1, receiver
   InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
   recvSink->Bind (local);
   recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
  
   Ptr<Socket> source = Socket::CreateSocket (networkNodes.Get (0), tid);    // node 0, sender
   InetSocketAddress remote = InetSocketAddress (Ipv4Address::GetBroadcast (), 90);
   source->SetAllowBroadcast (true);
   source->Connect (remote);

   //uint16_t sinkPort = 8080;
   //Address sinkAddress (InetSocketAddress(interfaces.GetAddress (1), sinkPort));

  
   /***************************************************************************/
   // all sources are connected to node 1
   // energy source
   Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource> (sources.Get (1));
   basicSourcePtr->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergy));
   // device energy model
   Ptr<DeviceEnergyModel> basicRadioModelPtr =
     basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
   NS_ASSERT (basicRadioModelPtr != NULL);
   basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption", MakeCallback (&TotalEnergy));
   /***************************************************************************/
  
  

   // start traffic
   Simulator::Schedule (Seconds (startTime), &GenerateTraffic, source, PpacketSize,
                        networkNodes.Get (0), numPackets, interPacketInterval);

   ///// memory usage
   using std::cout;
   using std::endl;

   double vm, rss;
   process_mem_usage(vm, rss);
   std::cout << "VM: " << vm << "; RSS: " << rss << std::endl;
   /////

   Simulator::Stop (Seconds (20.0));
   Simulator::Run ();
  
   for (DeviceEnergyModelContainer::Iterator iter = deviceModels.Begin (); iter != deviceModels.End (); iter ++)
     {
       double energyConsumed = (*iter)->GetTotalEnergyConsumption ();
       NS_LOG_UNCOND ("End of simulation (" << Simulator::Now ().GetSeconds ()
                      << "s) Total energy consumed by radio = " << energyConsumed << "J");
       //NS_ASSERT (energyConsumed <= 0.1);
     }


   ///// Stop clock
   auto stop = high_resolution_clock::now();
   auto duration = duration_cast<microseconds>(stop - start);
   cout << "Time=" << duration.count()/1000 << "milliseconds" << endl;
   /////
  
   Simulator::Destroy ();
  
   return 0;
 }


