#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../lua/lauxlib.h"
#include "../lua/lua.h"
#include "../lua/lualib.h"

#include "options.h"
#include "address.h"
#include "aes/aes.h"
#include "base32.h"
#include "base58.h"
#include "bignum.h"
#include "bip32.h"
#include "bip39.h"
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "ecdsa.h"
/*
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/curve25519-donna-scalarmult-base.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "ed25519-donna/ed25519.h"
*/
#include "hmac_drbg.h"
#include "memzero.h"
/* #include "monero/monero.h" */
#include "nem.h"
#include "nist256p1.h"
#include "pbkdf2.h"
#include "rand.h"
#include "rc4.h"
#include "rfc6979.h"
#include "script.h"
#include "secp256k1.h"
#include "sha2.h"
#include "sha3.h"
#include "shamir.h"
#include "slip39.h"

// #define USE_ETHEREUM  1

#define FROMHEX_MAXLEN 512

#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

#define MOTE_VERSION_PUBLIC 0x03A3FDC2
#define MOTE_VERSION_PRIVATE 0x03A3F988

#define DECRED_VERSION_PUBLIC 0x02fda926
#define DECRED_VERSION_PRIVATE 0x02fda4e8

#define ETHEREUM_VERSION_PUBLIC 0x0488b21e
#define ETHEREUM_VERSION_PRIVATE 0x0488ade4

const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

void tohex(char *hexbuf, uint8_t *str, int strlen){
  //char hexbuf[strlen];
    for (int i = 0 ; i < strlen/2 ; i++) {
        sprintf(&hexbuf[2*i], "%02X", str[i]);
    }
  hexbuf[strlen-2] = '\0';
}

// Lua-Trezor BIP-0032 primitives
int lua_hdnode_from_xpub(lua_State *L) {
  const int depth = lua_tonumber(L, -5);
  const int child_num = lua_tonumber(L, -4);
  const char *chain_code = lua_tostring(L, -3);
  const char *public_key = lua_tostring(L, -2);
  const char *curve_info = lua_tostring(L, -1);

  HDNode node;

  hdnode_from_xpub(0, 0, fromhex(chain_code), fromhex(public_key),
                              curve_info, &node);

  hdnode_fill_public_key(&node);

  for (int i = 0 ; i < 32 ; i++) {
     printf("%02x", node.private_key[i]);
  }
  printf("\n");

  lua_newtable(L);

  lua_pushstring(L, curve_info);
  lua_pushstring(L, public_key);
  lua_pushstring(L, chain_code);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    

  lua_setfield(L, -6, "depth");
  lua_setfield(L, -5, "child_num");
  lua_setfield(L, -4, "chain_code");
  lua_setfield(L, -3, "private_key");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
} 

int lua_hdnode_from_xprv(lua_State *L) {
  const int depth = lua_tonumber(L, -5);
  const int child_num = lua_tonumber(L, -4);
  const char *chain_code = lua_tostring(L, -3);
  const char *private_key = lua_tostring(L, -2);
  const char *curve_info = lua_tostring(L, -1);
  const char *public_key;
  const char *private_key_extension;

  
  HDNode node;

  hdnode_from_xprv(0, 0, fromhex(chain_code), fromhex(private_key),
                              curve_info, &node);

  hdnode_fill_public_key(&node);

  printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  lua_newtable(L);

  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    

  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_from_seed(lua_State *L) {
  const char *seed = lua_tostring(L, -3);
  const int seed_len = lua_tonumber(L,-2);
  const char *curve_info = lua_tostring(L, -1);

  const int depth;
  const int child_num;
  const char *chain_code;
  const char *private_key;
  const char *public_key;
  const char *private_key_extension;
 
  HDNode node; 

  hdnode_from_seed(fromhex(seed), seed_len,
                   curve_info, &node);

  hdnode_fill_public_key(&node);

  printf("\n");
  char chain_code_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&chain_code_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  chain_code_hex[64] = '\0';
  printf("\n");

  printf("\n");
  char private_key_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  private_key_hex[64] = '\0';
  printf("\n");

  printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  lua_newtable(L);


  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key_hex);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code_hex);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    

  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code_hex");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key_hex");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 
  

  return 1;

}

int lua_hdnode_private_ckd(lua_State *L) {
  const int depth = lua_tonumber(L, -8);
  const int child_num = lua_tonumber(L, -7);
  const char *chain_code = lua_tostring(L, -6);
  const char *private_key = lua_tostring(L, -5);
  const char *private_key_extension = lua_tostring(L, -4);
  const char public_key[33] = {0};
  const char *curve_info = lua_tostring(L, -2);
  const int derive_child_num = lua_tonumber(L, -1);

  HDNode node;

  // HDnode mapping from Lua to C struct
  node.depth = (uint32_t *) depth;
  node.child_num = (uint32_t *) child_num;
  int i =  derive_child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = curve_info;

  // hardened derivation key number
  // 2147483648 0x80000001
  // 2415919103 0x8FFFFFFF


  hdnode_from_xprv(0, 0, node.chain_code, node.private_key,
                              curve_info, &node);
  hdnode_private_ckd(&node, i);
  hdnode_fill_public_key(&node);

  printf("\n");printf("Chain Code:  ");printf("\n");
  char chain_code_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&chain_code_hex[2*i], "%02X", node.chain_code[i]);
      printf("%02x", node.chain_code[i]);
  }
  chain_code_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key:");printf("\n");
  char private_key_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  private_key_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key Extension:");printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Public Key:");printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  printf("\n");printf("Depth:");printf("\n");
  printf("%i",node.depth);
  printf("\n");printf("Child Num:");printf("\n");
  printf("%i",node.child_num);
  printf("\n");printf("Derive Child Num:");printf("\n");
  printf("%i",derive_child_num);printf("\n");

  lua_newtable(L);


  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key_hex);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code_hex);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    

  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code_hex");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key_hex");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_public_ckd_cp(lua_State *L) {
  const char *curve = lua_tostring(L, -6);
  const char *curve_point = lua_tostring(L, -5);
  const char *parent_chain_code = lua_tostring(L, -4);
  const int i = lua_tonumber(L, -3);
  const char *child = lua_tostring(L, -2);
  const char *child_chain_code = lua_tostring(L, -1);

  hdnode_public_ckd_cp(fromhex(curve), fromhex(curve_point), fromhex(parent_chain_code),
                       i, fromhex(child), fromhex(child_chain_code));

  lua_pushinteger(L, child_chain_code);
  lua_setfield(L, -6, "child_chain_code");
  
  return 1;
}

int lua_hdnode_public_ckd(lua_State *L) {
  const int depth = lua_tonumber(L, -8);
  const int child_num = lua_tonumber(L, -7);
  const char *chain_code = lua_tostring(L, -6);
  const char *private_key = lua_tostring(L, -5);
  const char *private_key_extension = lua_tostring(L, -4);
  const char *public_key = lua_tostring(L, -3);
  const char *curve_info = lua_tostring(L, -2);
  const int derive_child_num = lua_tonumber(L, -1);

  HDNode node;

  // HDnode mapping from Lua to C struct
  node.depth = (uint32_t *) depth;
  node.child_num = (uint32_t *) child_num;
  int i =  derive_child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  //memcpy(node.public_key,fromhex("0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2"), 33);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = curve_info;

  hdnode_from_xpub(0, 0, node.chain_code, node.public_key,
                              curve_info, &node);
  hdnode_private_ckd(&node, i);
  hdnode_fill_public_key(&node);

  printf("\n");printf("Chain Code:  ");printf("\n");
  char chain_code_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&chain_code_hex[2*i], "%02X", node.chain_code[i]);
      printf("%02x", node.chain_code[i]);
  }
  chain_code_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key:");printf("\n");
  char private_key_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  private_key_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key Extension:");printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Public Key:");printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  printf("\n");printf("Depth:");printf("\n");
  printf("%i",node.depth);
  printf("\n");printf("Child Num:");printf("\n");
  printf("%i",node.child_num);
  printf("\n");printf("Derive Child Num:");printf("\n");
  printf("%i",derive_child_num);printf("\n");

  lua_newtable(L);


  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key_hex);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code_hex);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    

  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code_hex");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key_hex");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_public_ckd_address_optimized(lua_State *L) {
  const char *pub = lua_tostring(L, -9);
  const char *chain_code = lua_tostring(L, -8);
  const int i = lua_tonumber(L, -7);
  const int version = lua_tonumber(L, -6);
  const char *hasher_pubkey = lua_tostring(L, -5);
  const char *hasher_base58 = lua_tostring(L, -4);
  const char *addr = lua_tostring(L, -3);
  const int addrsize = lua_tonumber(L, -2);
  const int addrformat = lua_tonumber(L, -1);

  hdnode_public_ckd_address_optimized(fromhex(pub), fromhex(chain_code), 
                      i, version,
                      fromhex(hasher_pubkey), fromhex(hasher_base58),
                      fromhex(addr), addrsize, addrformat);

  lua_pushinteger(L, hasher_base58);
  lua_setfield(L, -6, "hasher_base58");
  
  return 1;
}

int lua_hdnode_private_ckd_cached(lua_State *L) {
  const int depth = lua_tonumber(L, -10);
  const int child_num = lua_tonumber(L, -9);
  const char *chain_code = lua_tostring(L, -8);
  const char *private_key = lua_tostring(L, -7);
  const char *private_key_extension = lua_tostring(L, -6);
  const char *public_key = lua_tostring(L, -5);
  const char *curve_info = lua_tostring(L, -4);
  const int i = lua_tonumber(L, -3);
  const int i_count = lua_tonumber(L, -2);
  const int fingerprint = lua_tonumber(L, -1);

  HDNode node;

  // HDnode mapping from Lua to C struct
  node.depth = (uint32_t *) depth;
  node.child_num = (uint32_t *) child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  //memcpy(node.public_key,fromhex("0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2"), 33);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = curve_info;

  hdnode_from_xprv(0, 0, node.chain_code, node.private_key,
                              curve_info, &node);
  hdnode_private_ckd_cached(&node, i, i_count, fingerprint);
  //hdnode_fill_public_key(&node);

  printf("\n");printf("Chain Code:  ");printf("\n");
  char chain_code_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&chain_code_hex[2*i], "%02X", node.chain_code[i]);
      printf("%02x", node.chain_code[i]);
  }
  chain_code_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key:");printf("\n");
  char private_key_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  private_key_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key Extension:");printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Public Key:");printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  printf("\n");printf("Depth:");printf("\n");
  printf("%i",node.depth);
  printf("\n");printf("Child Num:");printf("\n");
  printf("%i",node.child_num);
  printf("\n");printf("Derive Child Num:");printf("\n");

  lua_newtable(L);

  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key_hex);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code_hex);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    
  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code_hex");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key_hex");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_fingerprint(lua_State *L) {
  const int depth = lua_tonumber(L, -7);
  const int child_num = lua_tonumber(L, -6);
  const char *chain_code = lua_tostring(L, -5);
  const char *private_key = lua_tostring(L, -4);
  const char *private_key_extension = lua_tostring(L, -3);
  const char *public_key = lua_tostring(L, -2);
  const char *curve_info = lua_tostring(L, -1);

  HDNode node;

  node.depth = depth;
  node.child_num =  child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = &curve_info;

  hdnode_from_xprv(depth, child_num, node.chain_code, node.private_key,
                              curve_info, &node);

  int fingerprint = hdnode_fingerprint(&node);
  printf("\n");printf("Fingerprint:");printf("\n");
  printf("%i", fingerprint);printf("\n");

  lua_newtable(L);
  lua_pushinteger(L, fingerprint);
  lua_setfield(L, -2, "fingerprint");
  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_fill_public_key(lua_State *L) {
  const int depth = lua_tonumber(L, -7);
  const int child_num = lua_tonumber(L, -6);
  const char *chain_code = lua_tostring(L, -5);
  const char *private_key = lua_tostring(L, -4);
  const char *private_key_extension = lua_tostring(L, -3);
  const char *public_key = lua_tostring(L, -2);
  const char *curve_info = lua_tostring(L, -1);

  HDNode node;

  node.depth = depth;
  node.child_num =  child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = &curve_info;

  hdnode_fill_public_key(&node);

  printf("\n");printf("Chain Code:  ");printf("\n");
  char chain_code_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&chain_code_hex[2*i], "%02X", node.chain_code[i]);
      printf("%02x", node.chain_code[i]);
  }
  chain_code_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key:");printf("\n");
  char private_key_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_hex[2*i], "%02X", node.private_key[i]);
      printf("%02x", node.private_key[i]);
  }
  private_key_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Private Key Extension:");printf("\n");
  char private_key_extension_hex[64];
  for (int i = 0 ; i < 32 ; i++) {
      sprintf(&private_key_extension_hex[2*i], "%02X", node.private_key_extension[i]);
      printf("%02x", node.private_key_extension[i]);
  }
  private_key_extension_hex[64] = '\0';
  printf("\n");

  printf("\n");printf("Public Key:");printf("\n");
  char public_key_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&public_key_hex[2*i], "%02X", node.public_key[i]);
      printf("%02x", node.public_key[i]);
  }
  public_key_hex[66] = '\0';
  printf("\n");

  printf("\n");printf("Depth:");printf("\n");
  printf("%i",node.depth);
  printf("\n");printf("Child Num:");printf("\n");
  printf("%i",node.child_num);
  printf("\n");printf("Derive Child Num:");printf("\n");

  lua_newtable(L);

  lua_pushstring(L,  curve_info);
  lua_pushstring(L,  private_key_hex);
  lua_pushstring(L,  private_key_extension_hex);
  lua_pushstring(L,  public_key_hex);
  lua_pushstring(L,  chain_code_hex);
  lua_pushinteger(L, child_num);
  lua_pushinteger(L, depth);
    
  lua_setfield(L, -8, "depth");
  lua_setfield(L, -7, "child_num");
  lua_setfield(L, -6, "chain_code_hex");
  lua_setfield(L, -5, "public_key_hex");
  lua_setfield(L, -4, "private_key_extension_hex");
  lua_setfield(L, -3, "private_key_hex");
  lua_setfield(L, -2, "curve_info");

  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_get_ethereum_pubkeyhash(lua_State *L) {
  const int depth = lua_tonumber(L, -7);
  const int child_num = lua_tonumber(L, -6);
  const char *chain_code = lua_tostring(L, -5);
  const char *private_key = lua_tostring(L, -4);
  const char *private_key_extension = lua_tostring(L, -3);
  const char *public_key = lua_tostring(L, -2);
  const char *curve_info = lua_tostring(L, -1);
  const char *pubkeyhash;

  HDNode node;

  node.depth = depth;
  node.child_num =  child_num;
  memcpy(node.chain_code,fromhex(chain_code), 32);
  memcpy(node.private_key,fromhex(private_key), 32);
  memcpy(node.private_key_extension,fromhex(private_key_extension), 32);
  memcpy(node.public_key,fromhex(public_key), 33);
  node.curve = &curve_info;

  hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);


  printf("\n");printf("Ethereum Pubkey Hash:");printf("\n");
  char pubkeyhash_hex[66];
  for (int i = 0 ; i < 33 ; i++) {
      sprintf(&pubkeyhash_hex[2*i], "%02X", pubkeyhash[i]);
      printf("%02x", pubkeyhash[i]);
  }
  pubkeyhash_hex[66] = '\0';
  printf("\n");

  lua_newtable(L);
  lua_pushinteger(L, pubkeyhash_hex);
  lua_setfield(L, -2, "pubkeyhash_hex");
  luaL_setmetatable(L, "lua_hdnode"); 

  return 1;
}

int lua_hdnode_sign(lua_State *L) {
  const int depth = lua_tonumber(L, -14);
  const int child_num = lua_tonumber(L, -13);
  const char *chain_code = lua_tostring(L, -12);
  const char *private_key = lua_tostring(L, -11);
  const char *private_key_extension = lua_tostring(L, -10);
  const char *public_key = lua_tostring(L, -9);
  const char *curve_info = lua_tostring(L, -8);
  const char *msg = lua_tostring(L, -7);
  const int msg_len = lua_tonumber(L, -6);
  const char *hasher_sign = lua_tostring(L, -5);
  const char *sig = lua_tostring(L, -4);
  const char *pby = lua_tostring(L, -3);
  const char *by = lua_tostring(L, -2);
  char *sig64 = lua_tostring(L, -1);

  /* to be implemented! */


  return 0;
}

int lua_hdnode_sign_digest(lua_State *L) {
  const int depth = lua_tonumber(L, -12);
  const int child_num = lua_tonumber(L, -11);
  const char *chain_code = lua_tostring(L, -10);
  const char *private_key = lua_tostring(L, -9);
  const char *private_key_extension = lua_tostring(L, -8);
  const char *public_key = lua_tostring(L, -7);
  const char *curve_info = lua_tostring(L, -6);
  const char *digest = lua_tostring(L, -5);
  const char *sig = lua_tostring(L, -4);
  const char *pby = lua_tostring(L, -3);
  const char *by = lua_tostring(L, -2);
  char *sig64 = lua_tostring(L, -1);

  /* to be implemented! */


  return 0;
}

int lua_hdnode_get_shared_key(lua_State *L) {
  const int depth = lua_tonumber(L, -10);
  const int child_num = lua_tonumber(L, -9);
  const char *chain_code = lua_tostring(L, -8);
  const char *private_key = lua_tostring(L, -7);
  const char *private_key_extension = lua_tostring(L, -6);
  const char *public_key = lua_tostring(L, -5);
  const char *curve_info = lua_tostring(L, -4);
  const char *peer_public_key = lua_tostring(L, -3);
  const char *session_key = lua_tostring(L, -2);
  const int resultsize = lua_tonumber(L, -1);


  /* to be implemented! */


  return 0;
}

int lua_hdnode_serialize_public(lua_State *L) {
  /* to be implemented! */
  return 0;
}

int lua_hdnode_serialize_private(lua_State *L) {
  /* to be implemented! */
  return 0;
}

int lua_hdnode_deserialize(lua_State *L) {
  /* to be implemented! */
  return 0;
}

int lua_hdnode_get_address_raw(lua_State *L) {
  /* to be implemented! */
  return 0;
}

int lua_hdnode_get_address(lua_State *L) {
  /* to be implemented! */
  return 0;
}


// Lua: set_my_text
int set_my_text(lua_State *L) {
  const char *my_text = lua_tostring(L, 1);
  char cmd[1024];
  snprintf(cmd, 1024, "echo Bridge code Trezor Crypto into Lua:%s", my_text);
  system(cmd);
  printf("PASSED ALL TESTS\n");
  return 0;
}

int get_mnemonic(lua_State *L) {
  const char *base_ext = lua_tostring(L, 1);
  const char *m;
  uint8_t seed[64];
  char base_int[] = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

  m = mnemonic_from_data(fromhex(base_ext), strlen(base_ext) / 2);

  
  mnemonic_to_seed(m, "TREZOR", seed, 0);

  printf("\n%s\n\n", m);
  
  return 0;
}


int get_coin_address(lua_State *L) {
  const char *coin = lua_tostring(L, 1);
  
  if (strcmp(coin,"bitcoin") == 0) 
  {
    printf("Give back a bitcoin address\n");
  }
  else if (strcmp(coin,"ethereum") == 0)
  {
    printf("Give back an ethereum address\n");
    uint8_t pubkeyhash[20];
    int res;
    HDNode node;

    // init m
    hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   SECP256K1_NAME, &node);

    // [Chain m]
    res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);

    for (int i = 0 ; i != 20 ; i++) {
      printf("%02x", pubkeyhash[i]);
    }
    printf("\n");

    // [Chain m]
    uint32_t fingerprint;
    fingerprint = 0;
    char str3[112];
    char str4[112];

    hdnode_fill_public_key(&node);
    hdnode_serialize_private(&node, fingerprint, ETHEREUM_VERSION_PRIVATE, str3,
                           sizeof(str3));

    hdnode_serialize_public(&node, fingerprint, ETHEREUM_VERSION_PUBLIC, str4,
                           sizeof(str4));

    char cmd3[1024];
    snprintf(cmd3, 1024, "echo Trezor master private key Ethereum:%s", str3);
    system(cmd3);
    char cmd4[1024];
    snprintf(cmd4, 1024, "echo Trezor master public key Ethereum:%s", str4);
    system(cmd4);

  }
  else if (strcmp(coin,"mote") == 0) 
  {
    printf("Give back a mote data\n");
    HDNode node;
  uint32_t fingerprint;
  char str[112];
  char str2[112];
  // int r;

  // init m
  hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   "ed25519", &node);

  // [Chain m]
  fingerprint = 0;
  hdnode_fill_public_key(&node);
  hdnode_serialize_private(&node, fingerprint, MOTE_VERSION_PRIVATE, str,
                           sizeof(str));

  hdnode_serialize_public(&node, fingerprint, MOTE_VERSION_PUBLIC, str2,
                           sizeof(str2));

  char cmd[1024];
  snprintf(cmd, 1024, "echo Trezor master private key R3C:%s", str);
  system(cmd);
  char cmd2[1024];
  snprintf(cmd2, 1024, "echo Trezor master public key R3C:%s", str2);
  system(cmd2);

  }
  return 0;
}

// Lua: create_master_privkey
int create_master_privkey(lua_State *L) {
  HDNode node;
  uint32_t fingerprint;
  char str[112];
  char str2[112];
  // int r;

  // init m
  hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   "secp256k1", &node);

  // [Chain m]
  fingerprint = 0;
  hdnode_fill_public_key(&node);
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  hdnode_serialize_public(&node, fingerprint, VERSION_PUBLIC, str2,
                           sizeof(str2));

  for (int i = 0 ; i != 32 ; i++) {
      printf("%02x", node.private_key[i]);
    }
    printf("\n");

  char cmd[1024];
  snprintf(cmd, 1024, "echo Trezor master private key Liquid:%s", str);
  system(cmd);
  char cmd2[1024];
  snprintf(cmd2, 1024, "echo Trezor master public key Liquid:%s", str2);
  system(cmd2);

  // [Chain m/44'/60'/]
  char str3[112];
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, 44);
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, 60);
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str3,
                           sizeof(str3));
  char cmd3[1024];
  snprintf(cmd3, 1024, "echo key derivation m/44h/60h :%s", str3);
  system(cmd3);

  // [Chain m/44'/60'/2147483650']
  char str4[112];
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, 2147483650);
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str4,
                           sizeof(str4));
  char cmd4[1024];
  snprintf(cmd4, 1024, "echo key derivation m/44h/60h/2147483650h :%s", str4);
  system(cmd4);

  // [Chain m/44'/60'/2147483650'/0/0]
  char str5[112];
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd(&node, 0);
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd(&node, 0);
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str5,
                           sizeof(str5));
  char cmd5[1024];
  snprintf(cmd5, 1024, "echo key derivation m/44h/60h/2147483650h/0/0 :%s", str5);
  system(cmd5);

  return 0;
}

// Lua: create_master_privkey
int create_master_privkey_mp(lua_State *L) {
  HDNode node;
  uint32_t fingerprint;
  char str[112];
  char str2[112];
  // int r;

  // init m
  hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   "ed25519", &node);

  // [Chain m]
  fingerprint = 0;
  hdnode_fill_public_key(&node);
  hdnode_serialize_private(&node, fingerprint, MOTE_VERSION_PRIVATE, str,
                           sizeof(str));
  hdnode_serialize_public(&node, fingerprint, MOTE_VERSION_PUBLIC, str2,
                           sizeof(str2));

  char cmd[1024];
  snprintf(cmd, 1024, "echo Trezor master private key Motes:%s", str);
  system(cmd);
  char cmd2[1024];
  snprintf(cmd2, 1024, "echo Trezor master public key Motes:%s", str2);
  system(cmd2);

  // [Chain m/44']
  char str3[112];
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, 44);
  hdnode_serialize_private(&node, fingerprint, MOTE_VERSION_PRIVATE, str3,
                           sizeof(str3));
  char cmd3[1024];
  snprintf(cmd3, 1024, "echo key derivation m/44h :%s", str3);
  system(cmd3);

  // [Chain m/44'/2147483650']
  char str4[112];
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, 2147483650);
  hdnode_serialize_private(&node, fingerprint, MOTE_VERSION_PRIVATE, str4,
                           sizeof(str4));
  char cmd4[1024];
  snprintf(cmd4, 1024, "echo key derivation m/44h/2147483650h :%s", str4);
  system(cmd4);


  return 0;
}


// Main.

int main() {

  // Create a Lua state and load the module.
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  luaL_dofile(L, "call_from_lua.lua");
  lua_setglobal(L, "call_from_lua");
  lua_settop(L, 0);

  // create metatable for hdnode
  luaL_newmetatable(L, "lua_hdnode");
  //luaL_newmetatable(L, "lua_hdnode");
  //lua_setfield(L, -2, "__index");
  //lua_setglobal(L, "lua_hdnode");


  // Make the Lua-Trezor BIP-0032 primitives
  lua_pushcfunction(L, lua_hdnode_from_xpub);
  lua_setglobal(L, "lua_hdnode_from_xpub");

  lua_pushcfunction(L, lua_hdnode_from_xprv);
  lua_setglobal(L, "lua_hdnode_from_xprv");

  lua_pushcfunction(L, lua_hdnode_from_seed);
  lua_setglobal(L, "lua_hdnode_from_seed");


  lua_pushcfunction(L, lua_hdnode_private_ckd);
  lua_setglobal(L, "lua_hdnode_private_ckd");

  lua_pushcfunction(L, lua_hdnode_public_ckd_cp);
  lua_setglobal(L, "lua_hdnode_public_ckd_cp");

  lua_pushcfunction(L, lua_hdnode_public_ckd);
  lua_setglobal(L, "lua_hdnode_public_ckd");

  lua_pushcfunction(L, lua_hdnode_public_ckd_address_optimized);
  lua_setglobal(L, "lua_hdnode_public_ckd_address_optimized");

  lua_pushcfunction(L, lua_hdnode_private_ckd_cached);
  lua_setglobal(L, "lua_hdnode_private_ckd_cached");

  lua_pushcfunction(L, lua_hdnode_fingerprint);
  lua_setglobal(L, "lua_hdnode_fingerprint");

  lua_pushcfunction(L, lua_hdnode_fill_public_key);
  lua_setglobal(L, "lua_hdnode_fill_public_key");

  lua_pushcfunction(L, lua_hdnode_get_ethereum_pubkeyhash);
  lua_setglobal(L, "lua_hdnode_get_ethereum_pubkeyhash");

  lua_pushcfunction(L, lua_hdnode_sign);
  lua_setglobal(L, "lua_hdnode_sign");

  lua_pushcfunction(L, lua_hdnode_sign_digest);
  lua_setglobal(L, "lua_hdnode_sign_digest");

  lua_pushcfunction(L, lua_hdnode_get_shared_key);
  lua_setglobal(L, "lua_hdnode_get_shared_key");

  lua_pushcfunction(L, lua_hdnode_serialize_public);
  lua_setglobal(L, "lua_hdnode_serialize_public");

  lua_pushcfunction(L, lua_hdnode_serialize_private);
  lua_setglobal(L, "lua_hdnode_serialize_private");

  lua_pushcfunction(L, lua_hdnode_deserialize);
  lua_setglobal(L, "lua_hdnode_deserialize");

  lua_pushcfunction(L, lua_hdnode_get_address_raw);
  lua_setglobal(L, "lua_hdnode_get_address_raw");

  lua_pushcfunction(L, lua_hdnode_get_address);
  lua_setglobal(L, "lua_hdnode_get_address");


  // Make the set_my_text function visible to Lua.
  lua_pushcfunction(L, set_my_text);
  lua_setglobal(L, "set_my_text");

  // Make the get_coin_address function visible to Lua.
  lua_pushcfunction(L, get_coin_address);
  lua_setglobal(L, "get_coin_address");

  // Make the get_mnemonic function visible to Lua.
  lua_pushcfunction(L, get_mnemonic);
  lua_setglobal(L, "get_mnemonic");

  // Make the create_master_privkey function visible to Lua.
  lua_pushcfunction(L, create_master_privkey);
  lua_setglobal(L, "create_master_privkey");

  // Make the create_master_privkey_mp function visible to Lua.
  lua_pushcfunction(L, create_master_privkey_mp);
  lua_setglobal(L, "create_master_privkey_mp");


  // Run the init() function.
  lua_getglobal(L, "call_from_lua");
  lua_getfield(L, -1, "init");  // -1 means stack top.
  lua_call(L, 0, 0);            // 0, 0 = #args, #retvals

  return 0;
}

// How to compile everything
// gcc call_from_lua.c -o call_from_lua -llua -L../lua -I../lua

// gcc  *.c  ed25519-donna/*.c -o call_from_lua -llua -L../lua -I../lua  -L./ed25519-donna -I../src -v

/*

cc call_from_lua.c hasher.c groestl.c nem.c pbkdf2.c rand.c rc4.c memzero.c nist256p1.c ecdsa.c secp256k1.c sha2.c sha3.c bip32.c bignum.c hmac.c curves.c base58.c ed25519-donna/ed25519.c ed25519-donna/curve25519-donna-scalarmult-base.c ed25519-donna/ed25519-keccak.c -o call_from_lua -llua -L../lua -I../lua  -L./ed25519-donna -I../src -v

https://stackoverflow.com/questions/40369986/passing-arbitrary-struct-from-c-to-lua-and-accessing-it

*/
