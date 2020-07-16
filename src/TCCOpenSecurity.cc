///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2020 Ericsson Telecom AB
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v2.0
// which accompanies this distribution, and is available at
// https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCOpenSecurity.cc
//  Description:        TCC Useful Functions: Security Functions
//
///////////////////////////////////////////////////////////////////////////////
#include "TCCOpenSecurity_Functions.hh"

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/modes.h>
#endif

namespace TCCOpenSecurity__Functions {

static void init_ssl_lib(){
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  return; // OpenSSL 1.1.0 and later initializes itself
#else

  static int inited=0;
  if(inited != 0){
    return;
  }
  inited =1;
  OpenSSL_add_all_algorithms();          // initialize library
#endif

}

int openssl_error_to_warning_cb(const char *str, size_t len, void *u){
  int ll=len;
  TTCN_warning("%.*s",ll,str);
  return 0;
}

static void openssl_error_to_warning(const char *str){
  TTCN_warning("%s",str);
  ERR_print_errors_cb(openssl_error_to_warning_cb,NULL);
  
}

static const char *uc2hex="0123456789abcdef";

CHARSTRING md5_to_hex(unsigned char * Bin){
 
  char Hex[MD5_DIGEST_LENGTH*2];
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    Hex[i*2] = uc2hex[(Bin[i] >> 4) & 0xf];
    Hex[i*2+1] = uc2hex[ Bin[i] & 0xf];
  }
  return CHARSTRING(MD5_DIGEST_LENGTH*2,Hex);
}

static const CHARSTRING dc_val=CHARSTRING(":");

CHARSTRING Calc_HA1(
    const CHARSTRING& alg,
    const CHARSTRING& username,
    const CHARSTRING& realm,
    const CHARSTRING& password,
    const CHARSTRING& nonce,
    const CHARSTRING& cnonce
    )
{
  CHARSTRING ha1_input=username+dc_val+realm+dc_val+password;
  unsigned char ha1[MD5_DIGEST_LENGTH];

  MD5((const unsigned char*)(const char *)ha1_input,ha1_input.lengthof(),ha1);
  if (alg == "md5-sess" ) {
    ha1_input=dc_val+nonce+dc_val+cnonce;
    MD5_CTX Md5Ctx;
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, ha1, MD5_DIGEST_LENGTH);
    MD5_Update(&Md5Ctx, ha1_input, ha1_input.lengthof());
    MD5_Final(ha1, &Md5Ctx);
  }  
  return md5_to_hex(ha1);
}

CHARSTRING Calculate_Digest_Response(
    const CHARSTRING& ha1,        /* H(A1) */
    const CHARSTRING& nonce,      /* nonce from server */
    const CHARSTRING& nonceCount, /* 8 hex digits */
    const CHARSTRING& cnonce,     /* client nonce */
    const CHARSTRING& qop,        /* qop-value: "", "auth", "auth-int" */
    const CHARSTRING& method,     /* method from the request */
    const CHARSTRING& digestUri,  /* requested URL */
    const CHARSTRING& hentity    /* H(entity body) if qop="auth-int" */
    )
{
  unsigned char md5_res[MD5_DIGEST_LENGTH];
  
  CHARSTRING h_input=method+dc_val+digestUri;
  
  if (qop == "auth-int") {
    h_input=h_input+dc_val+hentity;
  }
  MD5((const unsigned char*)(const char *)h_input,h_input.lengthof(),md5_res);
  
  h_input=ha1 + dc_val + nonce + dc_val;
  
  if (qop.lengthof()>0) {
    h_input=h_input+nonceCount+dc_val+cnonce+dc_val+qop+dc_val;
  }
  
  h_input=h_input+md5_to_hex(md5_res);
  
  MD5((const unsigned char*)(const char *)h_input,h_input.lengthof(),md5_res);
  
  return md5_to_hex(md5_res);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateDigestResponse
//
//  Purpose:
//    Calculate digest response
//
//  Parameters:
//      nonce - *in* *charstring* -   a server-specified data string which may
//  `                                 be uniquely generated each time a 401
//                                    response is made
//      cnonce - *in* *charstring* -  client nonce
//      user - *in* *charstring* -    user name
//      realm - *in* *charstring* -   user realm
//      passwd - *in* *charstring* -  user password
//      alg - *in* *charstring* -     a string indicating a pair of algorithms
//                                    used to produce the digest and a checksum
//      nonceCount - *in* *charstring* - nonce count (8 hex digits)
//      method - *in* *charstring* -  method (from the request)
//      qop - *in* *charstring* -     qop-value: "", "auth", "auth-int"
//      URI - *in* *charstring* -     digest URI
//      HEntity - *in* *charstring* - H(entity body) if qop="auth-int"
//
//  Return Value:
//    charstring - digest response
//
//  Errors:
//    -
//
//  Detailed description:
//    Support HTTP authentication (detailed description in RFC 2617) using
//    uses one-way hash (md5) specified in RFC 1321.
//    When a request arrives to server for an access-protected object, it
//    responds an "401 Unauthorized" status code and a WWW-Authenticate
//    header (encapsulate nonce and other necessary parameters). The client
//    is expected to retry the request, passing an Authorization header with
//    response field calculated with f_calculateDigestResponse().
//
//    Overview: http://en.wikipedia.org/wiki/Digest_access_authentication
//
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__calculateDigestResponse(
  const CHARSTRING& nonce,
  const CHARSTRING& cnonce,
  const CHARSTRING& user,
  const CHARSTRING& realm,
  const CHARSTRING& passwd,
  const CHARSTRING& alg,
  const CHARSTRING& nonceCount,
  const CHARSTRING& method,
  const CHARSTRING& qop,
  const CHARSTRING& URI,
  const CHARSTRING& HEntity)
{
  CHARSTRING ha1;

  ha1=Calc_HA1(alg,user,realm,passwd,nonce,cnonce);

  return Calculate_Digest_Response(ha1,nonce,nonceCount,cnonce,qop,method,URI,HEntity);

}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateDigestHA1
//
//  Purpose:
//    Calculate digest H(A1) hash
//
//  Parameters:
//      nonce - *in* *charstring* -   a server-specified data string which may
//  `                                 be uniquely generated each time a 401
//                                    response is made
//      cnonce - *in* *charstring* -  client nonce
//      user - *in* *charstring* -    user name
//      realm - *in* *charstring* -   user realm
//      passwd - *in* *charstring* -  user password
//      alg - *in* *charstring* -     a string indicating a pair of algorithms
//                                    used to produce the digest and a checksum
//
//  Return Value:
//    charstring - digest response
//
//  Errors:
//    -
//
//  Detailed description:
//    Overview: http://en.wikipedia.org/wiki/Digest_access_authentication
//
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__calculateDigestHA1(
  const CHARSTRING& nonce,
  const CHARSTRING& cnonce,
  const CHARSTRING& user,
  const CHARSTRING& realm,
  const CHARSTRING& passwd,
  const CHARSTRING& alg)
{
  return Calc_HA1(alg,user,realm,passwd,nonce,cnonce);

}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateMD5
//
//  Purpose:
//    Compute MD5 hash value
//
//  Parameters:
//      pszHashInput - *in* *charstring* -  input value to compute hash of
//
//  Return Value:
//      hashValue - *out* *charstring* -  hexa hash value of input
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
CHARSTRING  f__calculateMD5(const CHARSTRING& pszHashInput)
{
   unsigned char md[MD5_DIGEST_LENGTH];
   MD5((const unsigned char*)(const char *)pszHashInput,pszHashInput.lengthof(),md);


   return oct2str(OCTETSTRING(MD5_DIGEST_LENGTH,md));
}

OCTETSTRING  f__calculateMD5__oct(const OCTETSTRING& pszHashInput)
{
   unsigned char md[MD5_DIGEST_LENGTH];
   MD5((const unsigned char*)pszHashInput,pszHashInput.lengthof(),md);


   return OCTETSTRING(MD5_DIGEST_LENGTH,md);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateRAND__oct
//
//  Purpose:
//    Compute random value
//
//  Parameters:
//      pl__length - *in* *integer* -  length of random value
//
//  Return Value:
//      random value - *out* *octetstring* -  random value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING  f__calculateRAND__oct(const INTEGER& pl__length)
{
  int rand_length = (int)pl__length;
  unsigned char rand_val[rand_length];
  RAND_bytes(rand_val, rand_length);

  return OCTETSTRING(rand_length, rand_val);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateSHA1
//
//  Purpose:
//    Compute SHA1 hash value
//
//  Parameters:
//      pszHashInput - *in* *charstring* -  input value to compute hash of
//
//  Return Value:
//      hashValue - *out* *charstring* -  hexa hash value of input
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
CHARSTRING  f__calculateSHA1(const CHARSTRING& pszHashInput)
{
  unsigned char sha1[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)(const char *)pszHashInput,pszHashInput.lengthof(),sha1);

  return oct2str(OCTETSTRING(SHA_DIGEST_LENGTH,sha1));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateSHA1__oct
//
//  Purpose:
//    Compute SHA1 hash value and return in octetstring
//
//  Parameters:
//      pszHashInput - *in* *octetstring* -  input value to compute hash of
//
//  Return Value:
//      hashValue - *out* *octetstring* -  hash value of input in octetstring
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING  f__calculateSHA1__oct(const OCTETSTRING& pszHashInput)
{
  unsigned char sha1[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)pszHashInput,pszHashInput.lengthof(),sha1);

  return OCTETSTRING(SHA_DIGEST_LENGTH,sha1);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateHMACMD5
//
//  Purpose:
//      Calculate the HMAC MD5 value of a message with specified 64 bit key.
//
//  Parameters:
//      msg - *in* *octetstring* - message to be hashed
//      key - *in* *OCT_64*      - 64 bit key of the hash function
//
//  Return Value:
//      octetstring - Hash value (16 octet - 128 bit)
//
//  Errors:
//      -
//
//  Detailed description:
//      - (should be kept because of backward compatibility reasons)
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//      - key can only be 64 bit (any other case please use f_calculate_HMAC_MD5)
//      - the length of generated hash value can only be 128 bit (any other case please use f_calculate_HMAC_MD5)
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculateHMACMD5(const OCTETSTRING& msg, const OCT__64& key)
{
  unsigned char Response[16];
  int msglen = msg.lengthof();

  HMAC(EVP_md5(), key, 64, msg, msglen, Response, NULL);

  return OCTETSTRING(16, (const unsigned char *)Response);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__MD5
//
//  Purpose:
//      Calculate the HMAC MD5 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 16 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__MD5(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_md5(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__SHA1
//
//  Purpose:
//      Calculate the HMAC SHA1 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 16 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__SHA1(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha1(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__SHA256
//
//  Purpose:
//      Calculate the HMAC SHA256 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 32 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__SHA256(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__128__Encrypt__OpenSSL
//
//  Purpose: Calculate AES 128 CBC encrypted value
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__128__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY enc_key;
  unsigned char enc_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_encrypt_key(key, 128, &enc_key);

  AES_cbc_encrypt(data, enc_data,
    data_len, &enc_key,
    k_iv, AES_ENCRYPT);

  return OCTETSTRING(data_len, enc_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__128__Decrypt__OpenSSL
//
//  Purpose: Dectrypts AES 128 CBC encrypted data
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Encrypted Value
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__128__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY dec_key;
  unsigned char dec_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_decrypt_key(key, 128, &dec_key);

  AES_cbc_encrypt(data, dec_data,
    data_len, &dec_key,
    k_iv, AES_DECRYPT);

  return OCTETSTRING(data_len, dec_data);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__Encrypt__OpenSSL
//
//  Purpose: Calculate AES 128 CBC encrypted value with arbitrary key length
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{
  const unsigned char* key=(const unsigned char*)p_key;
  const int key_len_bit = p_key.lengthof() * 8;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY enc_key;
  unsigned char enc_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_encrypt_key(key, key_len_bit, &enc_key);

  AES_cbc_encrypt(data, enc_data,
    data_len, &enc_key,
    k_iv, AES_ENCRYPT);

  return OCTETSTRING(data_len, enc_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__Decrypt__OpenSSL
//
//  Purpose: Dectrypts AES CBC encrypted data with arbitrary key length
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Encrypted Value
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const int key_len_bit = p_key.lengthof() * 8;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY dec_key;
  unsigned char dec_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_decrypt_key(key, key_len_bit, &dec_key);

  AES_cbc_encrypt(data, dec_data,
    data_len, &dec_key,
    k_iv, AES_DECRYPT);

  return OCTETSTRING(data_len, dec_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__ECB__Encrypt
//
//  Purpose: Encrypts data using 3DES algorithm in ECB mode.
//
//  Parameters:
//          pl__data    - *in* *octetstring*   - Data to be encrypted
//          pl__key     - *in* *octetstring*   - Key
//
//  Return Value:
//         octetstring - encrypted data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__ECB__Encrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }

  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();

  if(EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
      if(pl__data.lengthof()%block_size){
        TTCN_warning("ef_3DES_ECB_Encrypt: The length of the pl_data should be n * %d (the block size) if padding is not used.", block_size);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
      if(!EVP_EncryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptUpdate failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
      position = outl;
      if(!EVP_EncryptFinal_ex(ctx, &outbuf[position], &outl)){
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptFinal_ex failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }

      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

    EVP_CIPHER_CTX_free(ctx);

  } else {
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}

///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__ECB__Decrypt
//
//  Purpose:  Dectrypts 3DES ECB encrypted data.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Encrytped data
//          pl__key       - *in* *octetstring*   - Key
//
//  Return Value:
//         octetstring - decrypted data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__ECB__Decrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if(EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    if(pl__data.lengthof()%block_size){
      TTCN_warning("ef_3DES_ECB_Decrypt: The length of the pl_data should be n * %d (the block size)!", block_size);
      EVP_CIPHER_CTX_free(ctx);
      return OCTETSTRING(0,NULL);
    }
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
      if(!EVP_DecryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptUpdate failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
      position = outl;

      if(!EVP_DecryptFinal_ex(ctx, &outbuf[position], &outl)){
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptFinal_ex failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }

      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

    EVP_CIPHER_CTX_free(ctx);

  } else {
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}



///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__CBC__Encrypt
//
//  Purpose: Encrypts data using TripleDES algorithm in CBC mode.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Data to be encrypted
//          pl__key       - *in* *octetstring*   - Key
//          pl__iv        - *in* *octetstring*   - Initialiazation Vector
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__CBC__Encrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if(EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
      if(pl__data.lengthof()%block_size){
        TTCN_warning("ef_3DES_CBC_Encrypt: The length of the pl_data should be n * %d (the block size) if padding is not used.", block_size);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
      if(!EVP_EncryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptUpdate failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }

      position = outl;

      if(!EVP_EncryptFinal_ex(ctx, &outbuf[position], &outl)){
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptFinal_ex failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }

      position += outl;
    }

    ret_val=OCTETSTRING(position, outbuf);
    Free(outbuf);
    EVP_CIPHER_CTX_free(ctx);

  } else {
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__3DES__CBC__Decrypt
//
//  Purpose: Decrypting TripleDES encypted data.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Encrypted Value
//          pl__key       - *in* *octetstring*   - Key
//          pl__iv        - *in* *octetstring*   - Initialiazation Vector
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__CBC__Decrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if(EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    if(pl__data.lengthof()%block_size){
      TTCN_warning("ef__3DES__CBC__Decrypt: The length of the pl_data should be n * %d (the block size)!", block_size);
      EVP_CIPHER_CTX_free(ctx);
      return OCTETSTRING(0,NULL);
    }
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
      if(!EVP_DecryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
        TTCN_warning("ef_3DES_CBC_Decrypt: EVP_DecryptUpdate failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
;
      position = outl;

      if(!EVP_DecryptFinal_ex(ctx, &outbuf[position], &outl)){
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptFinal_ex failed.");
        Free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
      }
      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

    EVP_CIPHER_CTX_free(ctx);

  } else {
        TTCN_warning("ef_3DES_CBC_Decrypt: EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef_Calculate__AES__XCBC__128
//
//  Purpose: Calculates the AES XCBC value of the data with a 128 bit key.
//
//  Parameters:
//          pl__data       - *in* *octetstring*   - Data
//          pl__key        - *in* *octetstring*   - Key
//          pl__out__length - *in* *integer*       - Length of the output
//
//  Return Value:
//         octetstring - AES XCBC value
//
//  Errors:
//      -
//
//  Detailed description:
//      AES XCBC generates a 16 byte long value which can be truncated
//      to a length given in pl__out__length.
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__Calculate__AES__XCBC__128 (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const INTEGER& pl__out__length)
{
  const int data_length = pl__data.lengthof();
  const unsigned char* data = (const unsigned char*)pl__data;
  const int block_size = 16;
  int outl;

  unsigned char key1[block_size] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
  unsigned char key2[block_size] = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
  unsigned char key3[block_size] = { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
  unsigned char e[block_size] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key1, &outl, key1, block_size);
  EVP_CIPHER_CTX_cleanup(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key2, &outl, key2, block_size);
  EVP_CIPHER_CTX_cleanup(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key3, &outl, key3, block_size);
  EVP_CIPHER_CTX_cleanup(ctx);

  if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL))
  {
    for(int i = 0; i < data_length - block_size; i += block_size)
    {
      for(int j = 0; j < block_size; j++)
      {
        e[j] ^= data[i+j];
      }

      EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
      EVP_EncryptUpdate(ctx, e, &outl, e, block_size);
      EVP_CIPHER_CTX_cleanup(ctx);
    }

    int last_block_length = data_length % block_size;

    if((last_block_length == 0) && (data_length != 0))
    {
      for(int i = 0; i < block_size; i++)
      {
        e[i] = data[data_length - block_size + i] ^ e[i] ^ key2[i];
      }
    } else {
      int i = 0;

      while(i < last_block_length)
      {
        e[i] = data[data_length - last_block_length + i] ^ e[i] ^ key3[i];
        i++;
      }

      e[i] = 0x80 ^ e[i] ^ key3[i];
      i++;


      while(i < block_size)
      {
        e[i] ^= key3[i];
        i++;
      }

    }
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
    EVP_EncryptUpdate(ctx, e, &outl, e, block_size);
    EVP_CIPHER_CTX_free(ctx);

    return OCTETSTRING(pl__out__length, (const unsigned char*)e);

  }
  EVP_CIPHER_CTX_free(ctx);
  return OCTETSTRING(0,NULL);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef_DH_generate_private_public_keys
//
//  Purpose: Generates public and private keys (this party).
//
//  Parameters:
//          pl__keyLength - *in* *integer*          - Key length (bytes)
//          pl__pubkey    - *inout* *octetstring*   - Public key (other party)
//          pl__privkey   - *inout* *octetstring*   - Private key (this party)
//
//  Return Value:
//         octetstring - DH shared secret
//
//  Errors:
//      -
//
//  Detailed description:
//      Computes the shared secret from the originating side's private key and
//      the public key of the responding side as described in DH group 1, 2 and 14.
//      Keys must be either 96, 128 or 256 bytes long.
//
///////////////////////////////////////////////////////////////////////////////
INTEGER ef__DH__generate__private__public__keys (const INTEGER& pl__keyLength, OCTETSTRING& pl__pubkey, OCTETSTRING& pl__privkey)
{
  int key_length = (int)pl__keyLength;

  const char* prime_768  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";

  const char* prime_1024 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

  const char* prime_2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

  DH* dh = DH_new();

  BIGNUM* prime = BN_new();
  switch(key_length)
  {
    case  96: BN_hex2bn(&prime, prime_768);  break;
    case 128: BN_hex2bn(&prime, prime_1024); break;
    case 256: BN_hex2bn(&prime, prime_2048); break;
    default:
    {
      DH_free(dh);
      return INTEGER(0);
    }
  }

  const char* generator = "2";
  BIGNUM* gen = BN_new();
  BN_hex2bn(&gen, generator);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  DH_set0_pqg(dh, prime, NULL, gen);
#else
  dh->p = prime;
  dh->g = gen;
#endif
  
  DH_generate_key(dh);
  const BIGNUM* pubk=NULL;
  const BIGNUM* privk=NULL;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  DH_get0_key(dh, &pubk, &privk);
#else
  pubk=dh->pub_key;
  privk=dh->priv_key;
#endif
  
  int pub_len = BN_num_bytes(pubk);
  unsigned char* pub_key = (unsigned char*)Malloc(pub_len * sizeof(unsigned char));
  pub_len = BN_bn2bin(pubk, pub_key);
  if (key_length-pub_len > 0)
  {pl__pubkey =  int2oct(0,key_length-pub_len) + OCTETSTRING(pub_len, pub_key);}
  else
  {pl__pubkey =  OCTETSTRING(key_length, pub_key);}
  Free(pub_key);

  if (pub_len <= 0)
  {
      DH_free(dh);
      return INTEGER(0);
  }

  int priv_len = BN_num_bytes(privk);
  unsigned char* priv_key = (unsigned char*)Malloc(priv_len * sizeof(unsigned char));
  priv_len = BN_bn2bin(privk, priv_key);
  if (key_length-priv_len > 0)
  {pl__privkey =  int2oct(0,key_length-priv_len) + OCTETSTRING(priv_len, priv_key);}
  else
  {pl__privkey =  OCTETSTRING(key_length, priv_key);}
  Free(priv_key);

  if (priv_len <= 0)
  {
      DH_free(dh);
      return INTEGER(0);
  }

  DH_free(dh);
  return INTEGER(1);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: ef_DH_shared_secret
//
//  Purpose: Calculates the shared secret from the given public and private keys.
//
//  Parameters:
//          pl__pubkey    - *in* *octetstring*   - Public key (other party)
//          pl__privkey   - *in* *octetstring*   - Private key (this party)
//
//  Return Value:
//         octetstring - DH shared secret
//
//  Errors:
//      -
//
//  Detailed description:
//      Computes the shared secret from the originating side's private key and
//      the public key of the responding side as described in DH group 1, 2 and 14.
//      Keys must be either 96, 128 or 256 bytes long.
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__DH__shared__secret (const OCTETSTRING& pl__pubkey, const OCTETSTRING& pl__privkey)
{
  int key_length = pl__pubkey.lengthof();
  unsigned char shared_secret[key_length];

  const char* prime_768  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";

  const char* prime_1024 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

  const char* prime_2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

  DH* dh = DH_new();

  BIGNUM* prime = BN_new();
  switch(key_length)
  {
    case  96: BN_hex2bn(&prime, prime_768);  break;
    case 128: BN_hex2bn(&prime, prime_1024); break;
    case 256: BN_hex2bn(&prime, prime_2048); break;
    default:
    {
      DH_free(dh);
      return OCTETSTRING(0, NULL);
    }
  }

  const char* generator = "2";
  BIGNUM* gen = BN_new();
  BN_hex2bn(&gen, generator);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  DH_set0_pqg(dh, prime, NULL, gen);
#else
  dh->p = prime;
  dh->g = gen;
#endif

  BIGNUM* priv_key = BN_new();
  BN_bin2bn((const unsigned char*)pl__privkey, key_length, priv_key);

  BIGNUM* pub_key = BN_new();
  BN_bin2bn((const unsigned char*)pl__pubkey, key_length, pub_key);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  DH_set0_key(dh, pub_key, priv_key );
#else
  dh->priv_key = priv_key;
  dh->pub_key = pub_key;
#endif

  if(DH_compute_key(shared_secret, pub_key, dh))
  {
    DH_free(dh);
    return OCTETSTRING(key_length, shared_secret);
  }

  DH_free(dh);
  return OCTETSTRING(0, NULL);

}


///////////////////////////////////////////////////////////////////////////////
//  Function: f_AES_ECB_128_Encrypt_OpenSSL
//
//  Purpose: Calculate AES 128 ECB encrypted value
//
//  Parameters:
//          p_key       - *in* *octetstring*   - Key
//          p_data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__ECB__128__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Encrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  const unsigned char* data=(const unsigned char*)p_data;
  int data_len = p_data.lengthof();

  int outbuf_len=data_len+AES_BLOCK_SIZE;

  unsigned char* outbuf=(unsigned char*)Malloc(outbuf_len * sizeof(unsigned char));

  int round=((data_len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;

  AES_KEY aes_k;
  AES_set_encrypt_key((const unsigned char*)p_key,128,&aes_k);

  for(int i=0;i<round; i++){
    if((i+1)*AES_BLOCK_SIZE > data_len){  // last partial block
      unsigned char b[AES_BLOCK_SIZE];
      memset(b,0,AES_BLOCK_SIZE);
      memcpy(b,data+(i*AES_BLOCK_SIZE),data_len-(i*AES_BLOCK_SIZE));
      AES_encrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    } else {  // full block
      AES_encrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    }
  }


  OCTETSTRING ret_val=OCTETSTRING(data_len,outbuf );
  return ret_val;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f_AES_ECB_128_Decrypt_OpenSSL
//
//  Purpose: Calculate AES 128 ECB decrypted value
//
//  Parameters:
//          p_key       - *in* *octetstring*   - Key
//          p_data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__ECB__128__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  const unsigned char* data=(const unsigned char*)p_data;
  int data_len = p_data.lengthof();

  int outbuf_len=data_len+AES_BLOCK_SIZE;

  unsigned char* outbuf=(unsigned char*)Malloc(outbuf_len * sizeof(unsigned char));

  int round=((data_len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;

  AES_KEY aes_k;
  AES_set_decrypt_key((const unsigned char*)p_key,128,&aes_k);

  for(int i=0;i<round; i++){
    if((i+1)*AES_BLOCK_SIZE > data_len){  // last partial block
      unsigned char b[AES_BLOCK_SIZE];
      memset(b,0,AES_BLOCK_SIZE);
      memcpy(b,data+(i*AES_BLOCK_SIZE),data_len-(i*AES_BLOCK_SIZE));
      AES_decrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    } else {  // full block
      AES_decrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    }
  }


  OCTETSTRING ret_val=OCTETSTRING(data_len,outbuf );
  return ret_val;
}
OCTETSTRING f__AES__CTR__128__Encrypt__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  if(p_iv.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the IV should be 16 instead of %d",p_iv.lengthof() );
  }
  AES_KEY aes_k;
  AES_set_encrypt_key((const unsigned char*)p_key,128,&aes_k);

  int data_len=p_data.lengthof();
  unsigned char enc_data[data_len];
  unsigned char k_iv[AES_BLOCK_SIZE];
  memcpy(k_iv,(const unsigned char*)p_iv,AES_BLOCK_SIZE);

  unsigned int num = 0;
  unsigned char ecount_buf[AES_BLOCK_SIZE];
  memset(ecount_buf, 0, AES_BLOCK_SIZE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
   CRYPTO_ctr128_encrypt((const unsigned char*)p_data, enc_data, data_len, &aes_k, k_iv,ecount_buf , &num, (block128_f)AES_encrypt);
#else
   AES_ctr128_encrypt((const unsigned char*)p_data, enc_data, data_len, &aes_k, k_iv, ecount_buf, &num);
#endif
  return OCTETSTRING(data_len, enc_data);
}


// The operation performed depends on the value of the enc parameter. It should be set to 1 for encryption, 0 for decryption
Cipher__Result f_cipher_data (const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const CHARSTRING p__cipher, const OCTETSTRING& pl__data__in, OCTETSTRING& pl__data__out, int enc, const Cipher__padding& p__padding)
{
  init_ssl_lib();
  pl__data__out=OCTETSTRING(0,NULL);
  if(pl__data__in.lengthof()==0){
    return Cipher__Result::Cipher__OK;
  }

  const EVP_CIPHER *cipher_type=EVP_get_cipherbyname((const char*)p__cipher);
  
  if(cipher_type==NULL){
    TTCN_warning("Unsupported cipher name: %s",(const char*)p__cipher);
    return Cipher__Result::Cipher__Not__Supported;
  }

 
  int iv_len=EVP_CIPHER_iv_length(cipher_type);
  
  if((iv_len!=0) && (iv_len!=pl__iv.lengthof())){
    TTCN_warning("The length of the iv should be %d instead of %d",iv_len,(int)pl__iv.lengthof());
    return Cipher__Result::Cipher__iv__length__error;
  }
  
  int key_len=EVP_CIPHER_key_length(cipher_type);
  if(key_len!=pl__key.lengthof()){
    TTCN_warning("The length of the key should be %d instead of %d",key_len,(int)pl__key.lengthof());
    return Cipher__Result::Cipher__key__length__error;
  }
  
  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();

  if(ctx==NULL){
    TTCN_warning("EVP_CIPHER_CTX_new error");
    return Cipher__Result::Cipher__Error;
  }

  EVP_CIPHER_CTX_init(ctx);  


  if(EVP_CipherInit_ex(ctx, cipher_type , NULL, pl__key, pl__iv,enc))
  {
    if(p__padding != Cipher__padding::Cipher__padding__PKCS) {  // The PKCS padding automatically handled by OpenSSL
      EVP_CIPHER_CTX_set_padding(ctx,0);  // The other padding type are handled manually
    }

    const unsigned char* data= (const unsigned char*)pl__data__in;
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    
    if((p__padding == Cipher__padding::Cipher__padding__none) && // No padding -> the data size must be multiple of block size
       (block_size) && (pl__data__in.lengthof() % block_size)){ // the data size must be multiple of block size 
       TTCN_warning("Data size error.");
       return Cipher__Result::Cipher__data__length__error;
    }
    
    unsigned char* outbuf = (unsigned char*)Malloc(pl__data__in.lengthof() + block_size); // never return NULL by definition. DTE instead of NULL.
                                              // The amount of data written depends on the block alignment of the encrypted data: as a result 
                                              // the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1) so 
                                              // out should contain sufficient room
    int outl = 0;
    int position = 0;

    if(!EVP_CipherUpdate(ctx, outbuf, &outl, data, pl__data__in.lengthof())){
      TTCN_warning("EVP_CipherUpdate failed.");
      Free(outbuf);
      EVP_CIPHER_CTX_free(ctx);
      return Cipher__Result::Cipher__Error;
    }

    position = outl;
    // Non PKCS padding & encryption => add the padding
    if( (enc == 1) && (p__padding != Cipher__padding::Cipher__padding__PKCS)){
      switch(p__padding){
        case Cipher__padding::Cipher__padding__ISO__IEC__7816__4:{
          unsigned char *padd_buff = (unsigned char*)Malloc(block_size);  // The maximum length of the padding is equal to the block size

          // padding pattern
          // the first byte is a mandatory byte valued '80' (Hexadecimal) followed, if needed, by 0 to N-1 bytes set to '00'
          memset(padd_buff,0,block_size);
          padd_buff[0] = 0x80;

          if(!EVP_CipherUpdate(ctx, &outbuf[position], &outl, padd_buff, block_size - (pl__data__in.lengthof() % block_size) )){
            TTCN_warning("EVP_CipherUpdate failed.");
            Free(outbuf);
            Free(padd_buff);
            EVP_CIPHER_CTX_free(ctx);
            return Cipher__Result::Cipher__Error;
          }
          
          Free(padd_buff);
          
          position += outl;

          break;
        }
        case Cipher__padding::Cipher__padding__none: // do nothing
        default:  // do nothing
          break;
      }
    }

    if(!EVP_CipherFinal_ex(ctx, &outbuf[position], &outl)){
      TTCN_warning("EVP_CipherFinal_ex failed.");
      Free(outbuf);
      EVP_CIPHER_CTX_free(ctx);
      return Cipher__Result::Cipher__Error;
    }

    position += outl;
   
    // Non PKCS padding & decryption => remove the padding
    if( (enc == 0) && (p__padding != Cipher__padding::Cipher__padding__PKCS)){
      switch(p__padding){
        case Cipher__padding::Cipher__padding__ISO__IEC__7816__4:{
          while( (position>0) &&  (outbuf[position-1] == 0x00) ){position--;} // search for the first non null byte from the end
          if((position == 0) || outbuf[position-1] != 0x80 ){  // which should be 0x08
            TTCN_warning("Padding pattern error.");            // else something is wrong with the padding
            Free(outbuf);
            EVP_CIPHER_CTX_free(ctx);
            return Cipher__Result::Cipher__padding__error;
          }
          
          position--; // skip the 0x08
          break;
        }
        case Cipher__padding::Cipher__padding__none: // do nothing
        default:  // do nothing
          break;
      }
    }
    
    
    pl__data__out=OCTETSTRING(position, outbuf);
    Free(outbuf);
    
  } else {
    TTCN_warning("EVP_CipherInit_ex failed.");
    EVP_CIPHER_CTX_free(ctx);
    return Cipher__Result::Cipher__Error;
  }


  EVP_CIPHER_CTX_free(ctx);

  return Cipher__Result::Cipher__OK;
}

Cipher__Result f__Encrypt__data (const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const CHARSTRING& p__cipher, const OCTETSTRING& pl__cleartext, OCTETSTRING& pl__ciphertext, const Cipher__padding& p__padding)
{
  return f_cipher_data(pl__key,pl__iv,p__cipher,pl__cleartext,pl__ciphertext,1,p__padding);
}

Cipher__Result f__Decrypt__data (const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const CHARSTRING& p__cipher, OCTETSTRING& pl__cleartext, const OCTETSTRING& pl__ciphertext, const Cipher__padding& p__padding)
{
  return f_cipher_data(pl__key,pl__iv,p__cipher,pl__ciphertext,pl__cleartext,0,p__padding);
}

Digest__Result f__Digest__data (const CHARSTRING& p__digest, const OCTETSTRING& pl__data, OCTETSTRING& pl__hash)
{
  init_ssl_lib();
  pl__hash=OCTETSTRING(0, NULL);
  const EVP_MD *digest_type=EVP_get_digestbyname((const char*)p__digest);
  
  if(digest_type==NULL){
    TTCN_warning("Unsupported digest name: %s",(const char*)p__digest);
    return Digest__Result::Digest__Not__Supported;
  }

 
  EVP_MD_CTX *ctx=EVP_MD_CTX_create();

  if(ctx==NULL){
    TTCN_warning("EVP_MD_CTX_new error");
    return Digest__Result::Digest__Error;
  }

  EVP_MD_CTX_init(ctx);  

  if(EVP_DigestInit_ex(ctx, digest_type , NULL))
  {
    const unsigned char* data= (const unsigned char*)pl__data;

    unsigned char outbuf[EVP_MAX_MD_SIZE];
    unsigned int outl = 0;

    if(!EVP_DigestUpdate(ctx, data, pl__data.lengthof())){
      TTCN_warning("EVP_DigestUpdate failed.");
      EVP_MD_CTX_destroy(ctx);
      return Digest__Result::Digest__Error;
    }


    if(!EVP_DigestFinal_ex(ctx, outbuf, &outl)){
      TTCN_warning("EVP_CipherFinal_ex failed.");
      EVP_MD_CTX_destroy(ctx);
      return Digest__Result::Digest__Error;
    }
    
    pl__hash=OCTETSTRING(outl, outbuf);
    
  } else {
    TTCN_warning("EVP_DigestInit_ex failed.");
    EVP_MD_CTX_destroy(ctx);
    return Digest__Result::Digest__Error;
  }


  EVP_MD_CTX_destroy(ctx);

  return Digest__Result::Digest__OK;
}

DigestSign__Result f__DigestSign__data (const CHARSTRING& p__digest, const OCTETSTRING& pl__key, const CHARSTRING& pl__passwd, const OCTETSTRING& pl__data, OCTETSTRING& pl__sign) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  init_ssl_lib();
  DigestSign__Result ret_val=DigestSign__Result::DigestSign__Error;

  pl__sign=OCTETSTRING(0, NULL);
  const EVP_MD *digest_type=EVP_get_digestbyname((const char*)p__digest);
  
  if(digest_type==NULL){
    TTCN_warning("Unsupported digest name: %s",(const char*)p__digest);
    return DigestSign__Result::DigestSign__Not__Supported;
  }

  
  BIO* bio = BIO_new(BIO_s_mem());
  if(bio){
    if(BIO_write(bio, (const unsigned char*)pl__key, pl__key.lengthof())>0){
      EVP_PKEY* pkey =  EVP_PKEY_new();
      if(pkey) {
        if (PEM_read_bio_PrivateKey(bio, &pkey, NULL, (void *)(const char*)pl__passwd)) {
          EVP_MD_CTX *md_ctx=EVP_MD_CTX_create();
          EVP_MD_CTX_init(md_ctx);
          if(EVP_DigestSignInit(md_ctx, NULL, digest_type, NULL, pkey) == 1){
            if(EVP_DigestSignUpdate(md_ctx, (const unsigned char*)pl__data, pl__data.lengthof()) == 1){
              size_t sig_len=0;
              if(EVP_DigestSignFinal(md_ctx, NULL, &sig_len)==1){
                unsigned char* buff=(unsigned char*)Malloc(sig_len*sizeof(unsigned char));
                if(EVP_DigestSignFinal(md_ctx, buff, &sig_len)==1){
                  pl__sign=OCTETSTRING(sig_len, buff);
                  ret_val=DigestSign__Result::DigestSign__OK;
                } else {
                  openssl_error_to_warning("f_DigestSign_data: EVP_DigestSignFinal failed");
                }
                Free(buff);
              } else {
                openssl_error_to_warning("f_DigestSign_data: EVP_DigestSignFinal failed");
              }
            } else {
              openssl_error_to_warning("f_DigestSign_data: EVP_DigestSignUpdate failed");
            }
          } else {
            openssl_error_to_warning("f_DigestSign_data: EVP_DigestSignInit failed");
          }
          EVP_MD_CTX_destroy(md_ctx);
        } else {
          openssl_error_to_warning("f_DigestSign_data: PEM_read_bio_PrivateKey failed");
        }

        EVP_PKEY_free(pkey);
      } else {
        openssl_error_to_warning("f_DigestSign_data: EVP_PKEY_new returned NULL");
      }
    } else {
      openssl_error_to_warning("f_DigestSign_data: BIO_write failed");
    }
    BIO_free(bio);
  } else {
    openssl_error_to_warning("f_DigestSign_data: BIO_new returned NULL");
  }

  return ret_val;
#else
  TTCN_error("The f_DigestSign_data requires at least OpenSSL 1.0.2");
  return DigestSign__Result::DigestSign__Not__Supported;
#endif
}

DigestSign__Result f__DigestSign__Verify__data (const CHARSTRING& p__digest, const OCTETSTRING& pl__key, const CHARSTRING& pl__passwd, const OCTETSTRING& pl__data, const OCTETSTRING& pl__sign) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  init_ssl_lib();
  DigestSign__Result ret_val=DigestSign__Result::DigestSign__Error;


  const EVP_MD *digest_type=EVP_get_digestbyname((const char*)p__digest);
  
  if(digest_type==NULL){
    TTCN_warning("f_DigestSign_Verify_data: Unsupported digest name: %s",(const char*)p__digest);
    return DigestSign__Result::DigestSign__Not__Supported;
  }

  
  BIO* bio = BIO_new(BIO_s_mem());
  if(bio){
    if(BIO_write(bio, (const unsigned char*)pl__key, pl__key.lengthof())>0){
      EVP_PKEY* pkey =  EVP_PKEY_new();
      if(pkey) {
        if (PEM_read_bio_PUBKEY(bio, &pkey, NULL, (void *)(const char*)pl__passwd)) {
          EVP_MD_CTX *md_ctx=EVP_MD_CTX_create();
          EVP_MD_CTX_init(md_ctx);
          if(EVP_DigestVerifyInit(md_ctx, NULL, digest_type, NULL, pkey) == 1){
            if(EVP_DigestVerifyUpdate(md_ctx, (const unsigned char*)pl__data, pl__data.lengthof()) == 1){
              int verifyres=EVP_DigestVerifyFinal(md_ctx, (const unsigned char*)pl__sign,pl__sign.lengthof() );
              switch(verifyres){
                case 1:
                  ret_val=DigestSign__Result::DigestSign__OK;
                  break;
                case 0:
                  ret_val=DigestSign__Result::DigestSign__Verification__Failed;
                  break;
                default:
                  openssl_error_to_warning("f_DigestSign_Verify_data: EVP_DigestVerifyFinal failed"); 
              }             
            } else {
              openssl_error_to_warning("f_DigestSign_Verify_data: EVP_DigestVerifyUpdate failed");
            }
          } else {
            openssl_error_to_warning("f_DigestSign_Verify_data: EVP_DigestVerifyInit failed");
          }
          EVP_MD_CTX_destroy(md_ctx);
        } else {
          openssl_error_to_warning("f_DigestSign_Verify_data: PEM_read_bio_PUBKEY failed");
        }

        EVP_PKEY_free(pkey);
      } else {
        openssl_error_to_warning("f_DigestSign_Verify_data: EVP_PKEY_new returned NULL");
      }
    } else {
      openssl_error_to_warning("f_DigestSign_Verify_data: BIO_write failed");
    }
    BIO_free(bio);
  } else {
    openssl_error_to_warning("f_DigestSign_Verify_data: BIO_new returned NULL");
  }

  return ret_val;
#else
  TTCN_error("The f_DigestSign_Verify_data requires at least OpenSSL 1.0.2");
  return DigestSign__Result::DigestSign__Not__Supported;
#endif
}

TCCOpenSecurity__Result f__generate__key__iv(
  const CHARSTRING& p__digest,
  const CHARSTRING& p__cipher,
  const OCTETSTRING& p__passwd,
  const OCTETSTRING& p__salt,
  const INTEGER& p__count,
  OCTETSTRING& p__key,
  OCTETSTRING& p__iv
  ){
  init_ssl_lib();
  TCCOpenSecurity__Result ret_val=TCCOpenSecurity__Result::TCCOpenSecurity__Result__Error;

  p__key=OCTETSTRING(0, NULL);
  p__iv=OCTETSTRING(0, NULL);
  const EVP_MD *digest_type=EVP_get_digestbyname((const char*)p__digest);
  
  if(digest_type==NULL){
    TTCN_warning("Unsupported digest name: %s",(const char*)p__digest);
    return TCCOpenSecurity__Result::DigestSign__Not__Supported;
  }
  const EVP_CIPHER *cipher_type=EVP_get_cipherbyname((const char*)p__cipher);
  
  if(cipher_type==NULL){
    TTCN_warning("Unsupported cipher name: %s",(const char*)p__cipher);
    return TCCOpenSecurity__Result::Cipher__Not__Supported;
  }
 
  const unsigned char *salt=NULL;
  if(p__salt.lengthof()==8){
    salt=(const unsigned char *)p__salt;
  } else if (p__salt.lengthof()==0) {
    salt=NULL;
  } else {
    TTCN_warning("Invalid p_salt length: %d",p__salt.lengthof());
    return TCCOpenSecurity__Result::Key__IV__Salt__length__error;
    
  }
  
 
  int iv_len=EVP_CIPHER_iv_length(cipher_type);
  int key_len=EVP_CIPHER_key_length(cipher_type);
  
  unsigned char key_data[EVP_MAX_KEY_LENGTH];
  unsigned char iv_data[EVP_MAX_IV_LENGTH];
  
  if(EVP_BytesToKey(cipher_type,digest_type,salt,(const unsigned char *)p__passwd,
                    p__passwd.lengthof(), (int)p__count,
                    key_data,iv_data)>0){
    ret_val=TCCOpenSecurity__Result::TCCOpenSecurity__Result__OK;
    p__key=OCTETSTRING(key_len, key_data);
    p__iv=OCTETSTRING(iv_len, iv_data);
  } else {
    openssl_error_to_warning("f_generate_key_iv: EVP_BytesToKey failed");
  }
  
  return ret_val;
}

TCCOpenSecurity__Result f__HMAC__data(
  const CHARSTRING& p__digest,
  const OCTETSTRING& p__key,
  const OCTETSTRING& p__data,
  OCTETSTRING& p__hmac
) {
  init_ssl_lib();
  TCCOpenSecurity__Result ret_val=TCCOpenSecurity__Result::TCCOpenSecurity__Result__Error;

  p__hmac=OCTETSTRING(0, NULL);
  const EVP_MD *digest_type=EVP_get_digestbyname((const char*)p__digest);
  
  if(digest_type==NULL){
    TTCN_warning("Unsupported digest name: %s",(const char*)p__digest);
    return TCCOpenSecurity__Result::DigestSign__Not__Supported;
  }

  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  if(HMAC(digest_type, (const unsigned char*)p__key, p__key.lengthof(), (const unsigned char*)p__data, p__data.lengthof(), output, &out_length)!=NULL){
    p__hmac=OCTETSTRING(out_length, output);
    ret_val=TCCOpenSecurity__Result::TCCOpenSecurity__Result__OK;
  } else {
    openssl_error_to_warning("f_HMAC_data: HMAC failed");
  }



  return ret_val;
}


}
