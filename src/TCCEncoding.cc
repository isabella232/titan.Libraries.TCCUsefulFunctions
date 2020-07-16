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
//  File:               TCCEncoding.cc
//  Description:        TCC Useful Functions: Message Encoding Functions.
/
///////////////////////////////////////////////////////////////////////////////

#include "TCCEncoding_Functions.hh"
#include <string.h>

namespace TCCEncoding__Functions {

CHARSTRING enc_Base64(const OCTETSTRING& msg, bool use_linebreaks, int alphabet);
OCTETSTRING dec_Base64(const CHARSTRING& b64, bool warn_invalid_char, int alphabet);

static const unsigned char* base_encode_tables[]= {
  (const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  (const unsigned char*)"0123456789ABCDEFGHIJKLMNOPQRSTUV",
  (const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  (const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};

static const unsigned char base_decode_tables[][128]={
  { 127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127,  26,  27,  28,  29,  30,  31,  127, 127, 127, 127, 127, 127, 127, 127,
    127,   0,   1,   2,   3,   4,   5,   6,    7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,   23,  24,  25, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127
  },
  { 127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
      0,   1,   2,   3,   4,   5,   6,   7,    8,   9, 127, 127, 127, 127, 127, 127,
    127,  10,  11,  12,  13,  14,  15,  16,   17,  18,  19,  20,  21,  22,  23,  24,
     25,  26,  27,  28,  29,  30,  31, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127,  127, 127, 127, 127, 127, 127, 127, 127
  },
  {
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 62, 80, 80, 80, 63,
    52, 53, 54, 55, 56, 57, 58, 59,   60, 61, 80, 80, 80, 70, 80, 80,
    80,  0,  1,  2,  3,  4,  5,  6,    7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, 80, 80, 80, 80, 80,
    80, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,   49, 50, 51, 80, 80, 80, 80, 80
  },
  {
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 62, 80, 80,
    52, 53, 54, 55, 56, 57, 58, 59,   60, 61, 80, 80, 80, 70, 80, 80,
    80,  0,  1,  2,  3,  4,  5,  6,    7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, 80, 80, 80, 80, 63,
    80, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,   49, 50, 51, 80, 80, 80, 80, 80
  }
};

////////////////////////////
// MIME Base64 (RFC 2045) //
////////////////////////////

///////////////////////////////////////////////////////////////////////////////
//  Function: enc__MIME__Base64
// 
//  Purpose:
//    Encode message to MIME Base64 format (RFC 2045)
//
//  Parameters:
//    p__msg - *in* *octetstring* - message to encode
// 
//  Return Value:
//    charstring - encoded message
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING enc__MIME__Base64(const OCTETSTRING& p__msg)
{
  return enc_Base64(p__msg, true,2);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: dec__MIME__Base64
// 
//  Purpose:
//    Decode message from MIME Base64 format (RFC 2045)
//
//  Parameters:
//    p__b64 - *in* *charstring* - message to decode
// 
//  Return Value:
//    octetstring - decoded message
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING dec__MIME__Base64(const CHARSTRING& p__b64)
{
  return dec_Base64(p__b64, false,2);
}

////////////////////////////
// LDIF Base64 (RFC 2849) //
////////////////////////////

///////////////////////////////////////////////////////////////////////////////
//  Function: enc__LDIF__Base64
// 
//  Purpose:
//    Encode message to LDIF Base64 format (RFC 2849)
//
//  Parameters:
//    p__msg - *in* *octetstring* - message to encode
// 
//  Return Value:
//    charstring - encoded message
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING enc__LDIF__Base64(const OCTETSTRING& p__msg)
{
  return enc_Base64(p__msg, false,2);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: dec__LDIF__Base64
// 
//  Purpose:
//    Decode message from LDIF Base64 format (RFC 2849)
//
//  Parameters:
//    p__b64 - *in* *charstring* - message to decode
// 
//  Return Value:
//    octetstring - decoded message
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING dec__LDIF__Base64(const CHARSTRING& p__b64)
{
  return dec_Base64(p__b64, true,2);
}

CHARSTRING enc__Base64(const OCTETSTRING& p__msg, const BaseEncoding__Alphabet& p__alphabet)
{
  if(p__alphabet!=BaseEncoding__Alphabet::Base64__Default &&  p__alphabet!=BaseEncoding__Alphabet::Base64__Url ){
    TTCN_error("enc_Base64: Wrong alphabet: %s",BaseEncoding__Alphabet::enum_to_str(p__alphabet));
  }
  return enc_Base64(p__msg, false,BaseEncoding__Alphabet::enum2int(p__alphabet));
}

OCTETSTRING dec__Base64(const CHARSTRING& p__b64, const BaseEncoding__Alphabet& p__alphabet)
{
  if(p__alphabet!=BaseEncoding__Alphabet::Base64__Default &&  p__alphabet!=BaseEncoding__Alphabet::Base64__Url ){
    TTCN_error("dec_Base64: Wrong alphabet: %s",BaseEncoding__Alphabet::enum_to_str(p__alphabet));
  }
  
  return dec_Base64(p__b64, true, BaseEncoding__Alphabet::enum2int(p__alphabet));
}

CHARSTRING enc__Base32(const OCTETSTRING& p__msg, const BaseEncoding__Alphabet& p__alphabet)
{
  if(p__alphabet!=BaseEncoding__Alphabet::Base32__Default &&  p__alphabet!=BaseEncoding__Alphabet::Base32__ExtendedHex ){
    TTCN_error("enc_Base32: Wrong alphabet: %s",BaseEncoding__Alphabet::enum_to_str(p__alphabet));
  }
  const unsigned char* code_table = base_encode_tables[BaseEncoding__Alphabet::enum2int(p__alphabet)];
  
  const char pad = '=';
  const unsigned char *p_msg = (const unsigned char *)p__msg;
  int octets_left = p__msg.lengthof();
  
  if(octets_left==0){  // Zero length in string -> zero length out string
    return "";
  }
  
  size_t out_len= ((octets_left+4) / 5) * 8; 
  
  TTCN_Buffer buff;
  unsigned char *p_output = NULL;
  buff.get_end(p_output,out_len);
  out_len=0;
  
  while(octets_left >= 5) {
    *p_output++ = code_table[(p_msg[0] >> 3) & 0x1f ];
    *p_output++ = code_table[((p_msg[0] << 2) | (p_msg[1] >> 6)) & 0x1f];
    *p_output++ = code_table[(p_msg[1] >> 1) & 0x1f ];
    *p_output++ = code_table[((p_msg[1] << 4) | (p_msg[2] >> 4)) & 0x1f];
    *p_output++ = code_table[((p_msg[2] << 1) | (p_msg[3] >> 7)) & 0x1f];
    *p_output++ = code_table[(p_msg[3] >> 2) & 0x1f ];
    *p_output++ = code_table[((p_msg[3] << 3) | (p_msg[4] >> 5)) & 0x1f];
    *p_output++ = code_table[p_msg[4] & 0x1f];

    p_msg+=5;
    octets_left-=5;
    out_len+=8;
  }  
  
  switch(octets_left) {
  case 1:
    *p_output++ = code_table[p_msg[0] >> 3];
    *p_output++ = code_table[(p_msg[0] << 2) & 0x1c];
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    out_len+=8;
    break;
  case 2:
    *p_output++ = code_table[(p_msg[0] >> 3) & 0x1f ];
    *p_output++ = code_table[((p_msg[0] << 2) | (p_msg[1] >> 6)) & 0x1f];
    *p_output++ = code_table[(p_msg[1] >> 1) & 0x1f ];
    *p_output++ = code_table[(p_msg[1] << 4) & 0x10];
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    out_len+=8;
    break;
  case 3:
    *p_output++ = code_table[(p_msg[0] >> 3) & 0x1f ];
    *p_output++ = code_table[((p_msg[0] << 2) | (p_msg[1] >> 6)) & 0x1f];
    *p_output++ = code_table[(p_msg[1] >> 1) & 0x1f ];
    *p_output++ = code_table[((p_msg[1] << 4) | (p_msg[2] >> 4)) & 0x1f];
    *p_output++ = code_table[(p_msg[2] << 1)  & 0x1e];
    *p_output++ = pad;
    *p_output++ = pad;
    *p_output++ = pad;
    out_len+=8;
    break;
  case 4:
    *p_output++ = code_table[(p_msg[0] >> 3) & 0x1f ];
    *p_output++ = code_table[((p_msg[0] << 2) | (p_msg[1] >> 6)) & 0x1f];
    *p_output++ = code_table[(p_msg[1] >> 1) & 0x1f ];
    *p_output++ = code_table[((p_msg[1] << 4) | (p_msg[2] >> 4)) & 0x1f];
    *p_output++ = code_table[((p_msg[2] << 1) | (p_msg[3] >> 7)) & 0x1f];
    *p_output++ = code_table[(p_msg[3] >> 2) & 0x1f ];
    *p_output++ = code_table[(p_msg[3] << 3) & 0x18];
    *p_output++ = pad;
    out_len+=8;
    break;
  default:
    break;
  }
  
  
  
  CHARSTRING ret_val;
  buff.increase_length(out_len);
  buff.get_string(ret_val);
  return ret_val;
  
}

OCTETSTRING dec__Base32(const CHARSTRING& p__b32, const BaseEncoding__Alphabet& p__alphabet)
{
  if(p__alphabet!=BaseEncoding__Alphabet::Base32__Default &&  p__alphabet!=BaseEncoding__Alphabet::Base32__ExtendedHex ){
    TTCN_error("dec_Base32: Wrong alphabet: %s",BaseEncoding__Alphabet::enum_to_str(p__alphabet));
  }
  const unsigned char* decode_table = base_decode_tables[BaseEncoding__Alphabet::enum2int(p__alphabet)];

  const unsigned char *p_p32 = (const unsigned char *) ((const char *) p__b32);
  int chars_left = p__b32.lengthof();
  
  if(chars_left==0){
    return OCTETSTRING(0,NULL);
  }

  size_t out_len= (chars_left / 8) * 5; 
  
  TTCN_Buffer buff;
  unsigned char *p_output = NULL;
  buff.get_end(p_output,out_len);
  out_len=0;
  

  unsigned int bits = 0;
  size_t n_bits = 0;
  bool non_base64_char = false;
  while(chars_left--) {
    unsigned char dec;
    if(*p_p32 > 0 && (dec = decode_table[*p_p32])<32) {
      bits <<= 5;
      bits |= dec;
      n_bits += 5;
      if(n_bits>=8) {
        *p_output++ = (bits >> (n_bits-8)) & 0xff;
        n_bits-=8;
        out_len++;
      }
    } else if (*p_p32 == '=') {
      break;
    } else {
      non_base64_char = true;
    }
    p_p32++;
  }
  if(non_base64_char) {
      TTCN_Logger::begin_event(TTCN_WARNING);
      TTCN_Logger::log_event_str("Warning: Invalid character in Base64 encoded "
        "data: ");
      p__b32.log();
      TTCN_Logger::end_event();
  }
  OCTETSTRING ret_val;
  buff.increase_length(out_len);
  buff.get_string(ret_val);
  return ret_val;
  
}



// implementation

CHARSTRING enc_Base64(const OCTETSTRING& msg, bool use_linebreaks, int alphabet)
{
  const unsigned char *code_table = base_encode_tables[alphabet];
  /*= {
    "ABCDEFGHIJKLMNOP"
    "QRSTUVWXYZabcdef"
    "ghijklmnopqrstuv"
    "wxyz0123456789+/"
  };*/
  const char pad = '=';
  const unsigned char *p_msg = (const unsigned char *)msg;
  int octets_left = msg.lengthof();
  //char *output = new char[(octets_left/3+1)*4 + (octets_left/76+1)*2 + 1];
  // quick approximation:
  char *output = new char[((octets_left*22)>>4) + 7];
  char *p_output = output;
  int n_4chars = 0;
  while(octets_left >= 3) {
    *p_output++ = code_table[p_msg[0] >> 2];
    *p_output++ = code_table[((p_msg[0] << 4) | (p_msg[1] >> 4)) & 0x3f];
    *p_output++ = code_table[((p_msg[1] << 2) | (p_msg[2] >> 6)) & 0x3f];
    *p_output++ = code_table[p_msg[2] & 0x3f];
    n_4chars++;
    if(use_linebreaks && n_4chars>=19 && octets_left != 3) {
      *p_output++ = '\r';
      *p_output++ = '\n';
      n_4chars = 0;
    }
    p_msg += 3;
    octets_left -= 3;
  }
  switch(octets_left) {
  case 1:
    *p_output++ = code_table[p_msg[0] >> 2];
    *p_output++ = code_table[(p_msg[0] << 4) & 0x3f];
    *p_output++ = pad;
    *p_output++ = pad;
    break;
  case 2:
    *p_output++ = code_table[p_msg[0] >> 2];
    *p_output++ = code_table[((p_msg[0] << 4) | (p_msg[1] >> 4)) & 0x3f];
    *p_output++ = code_table[(p_msg[1] << 2) & 0x3f];
    *p_output++ = pad;
    break;
  default:
    break;
  }
  *p_output = '\0';
  CHARSTRING ret_val(output);
  delete []output;
  return ret_val;
}

OCTETSTRING dec_Base64(const CHARSTRING& b64, bool warn_invalid_char, int alphabet)
{
  const unsigned char *decode_table = base_decode_tables[alphabet];
  /*{
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80,   80, 80, 80, 62, 80, 80, 80, 63,
    52, 53, 54, 55, 56, 57, 58, 59,   60, 61, 80, 80, 80, 70, 80, 80,
    80,  0,  1,  2,  3,  4,  5,  6,    7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, 80, 80, 80, 80, 80,
    80, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,   49, 50, 51, 80, 80, 80, 80, 80
  };*/
  const unsigned char *p_p32 = (const unsigned char *) ((const char *) b64);
  int chars_left = b64.lengthof();
  unsigned char *output = new unsigned char[((chars_left>>2)+1)*3];
  unsigned char *p_output = output;
  unsigned int bits = 0;
  size_t n_bits = 0;
  bool non_base64_char = false;
  while(chars_left--) {
    unsigned char dec;
    if(*p_p32 > 0 && (dec = decode_table[*p_p32])<64) {
      bits <<= 6;
      bits |= dec;
      n_bits += 6;
      if(n_bits>=8) {
        *p_output++ = (bits >> (n_bits-8)) & 0xff;
        n_bits-=8;
      }
    } else if (*p_p32 == '=') {
      break;
    } else {
      non_base64_char = true;
      if(warn_invalid_char){
        TTCN_warning("Invalid char %c",*p_p32);
      }
    }
    p_p32++;
  }
  if(warn_invalid_char && non_base64_char) {
      TTCN_Logger::begin_event(TTCN_WARNING);
      TTCN_Logger::log_event_str("Warning: Invalid character in Base64 encoded "
        "data: ");
      b64.log();
      TTCN_Logger::end_event();
  }
  OCTETSTRING ret_val(p_output - output, output);
  delete []output;
  return ret_val;
}




///////////////////////////////////////////////////////////////////////////////
//  Function: f__enc__TBCD
// 
//  Purpose:
//    Encode charstring to TBCD
//
//  Parameters:
//    pl__char - *in* *charstring* - message to encode
// 
//  Return Value:
//    octetstring - TBCD encoding
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__enc__TBCD(const CHARSTRING& pl__char)
{
 const unsigned char code_table[] = {
    0x00,0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08,0x09 
  };
 const char* p_char = (const char*) pl__char;
 int char_length = pl__char.lengthof();
 int oct_length;
 
 if ((char_length % 2) == 1){
  oct_length = (char_length + 1) / 2;
 }
 else {
  oct_length = (char_length) / 2;
 }
 
 unsigned char half_byte;
 unsigned char *output = new unsigned char[oct_length]; 
  
 for (int i = 0; i < char_length; i++) {    
   if((p_char[i] >= 0x30) && (p_char[i] <= 0x39)) {    
     half_byte =  code_table[p_char[i]-0x30];    
   }
   else if (p_char[i] == 0x2A)
     half_byte = 0x0A;
   else if (p_char[i] == 0x23)
     half_byte = 0x0B;
   else if (p_char[i] == 0x61)
     half_byte = 0x0C;
   else if (p_char[i] == 0x62)
     half_byte = 0x0D;
   else if (p_char[i] == 0x63) 
     half_byte = 0x0E;
   else {  
      TTCN_Logger::log(TTCN_WARNING,"Warning : Invalid TBCD digit!");
      delete []output;
      return OCTETSTRING(0,0);
   }
     
  if ((i % 2) == 0) {    
    output[i/2] = half_byte; 
    if((i+1) == char_length) {
      output[i/2] = output[i/2] | 0xF0;
    }    
  }
  else {   
    output[(i-1)/2] = output[(i-1)/2] | ( half_byte << 4);
  } 
 } 
  
  OCTETSTRING ret_val(oct_length, output);
  delete []output;
  return ret_val;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__dec__TBCD
// 
//  Purpose:
//    Decode octetstring from TBCD encoding
//
//  Parameters:
//    pl__oct - *in* *octetstring* - message to decode
// 
//  Return Value:
//    charstring - decoded message
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__dec__TBCD(const OCTETSTRING& pl__oct) 
{
 unsigned const char* p_char = (const unsigned char*) pl__oct;
 int oct_length = pl__oct.lengthof();
 char *output = new char[oct_length*2+1];
 
 const char *code_table = {
    "0123456789*#abc"
  };
 unsigned char msb;
 unsigned char lsb;
  
 int i = 0;
 while (i < oct_length) { 
    msb = (unsigned char)((p_char[i] & 0xF0) >> 4);
    lsb = (unsigned char)(p_char[i] & 0x0F);
        
    if(lsb != 0x0F){ // lsb not filler
      output[2*i] = code_table[lsb];
    }
    else { // lsb is filler 
      TTCN_Logger::log(TTCN_WARNING,"Warning : Filler digit at invalid location!");
      delete []output;
      return CHARSTRING("");
    } 
       
    if(msb != 0x0F) { // msb not filler
      output[2*i+1] = code_table[msb];
      if (i == (oct_length-1)) {
        output[2*i+2] = '\0';
      }      
    }
    else { // msb is filler    
      if (i == (oct_length-1))  {   
        output[2*i+1] = '\0';
      }
      else {
        TTCN_Logger::log(TTCN_WARNING,"Warning : Filler digit at invalid location!");
        delete []output;
        return CHARSTRING("");      
      }      
    }     
   i=i+1; 
 }  
  CHARSTRING ret_val(output);
  delete []output;
  return ret_val;   
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f_enc_percent
//
//  Purpose:
//    This function encodes the data into percent encoded string as specified in RFC 3986
//
//  Parameters:
//    pl_data- *charstring* - data to be encoded
//    pl_space_encoding - *charstring* - charstring to be used to encode the space character "+" or "%20"
//
//  Return Value:
//    *charstring* - percent encoded data
//
///////////////////////////////////////////////////////////////////////////////
static const char *c_2_hex="0123456789abcdef";

CHARSTRING f__enc__percent(const CHARSTRING& pl_data, const CHARSTRING& pl_space_encoding) {
  size_t input_length=pl_data.lengthof();
  if(input_length==0){
    return "";
  }

  size_t space_length=pl_space_encoding.lengthof()<4?pl_space_encoding.lengthof():3;
  const char* in_ptr=(const char*)pl_data;
  char *encoded_ptr=(char *)Malloc(3 * input_length * sizeof(char));
  size_t output_length=0;
  for(size_t i=0; i<input_length; i++){
    if(  // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
         (in_ptr[i] >= 'a' && in_ptr[i] <= 'z') || (in_ptr[i] >= 'A' && in_ptr[i] <= 'Z')   // ALPHA
         || (in_ptr[i] >= '0' && in_ptr[i] <= '9')  // DIGIT
         || (in_ptr[i] == '-') || (in_ptr[i] == '.') || (in_ptr[i] == '_') || (in_ptr[i] == '~') // -" / "." / "_" / "~"
        ){
      
      encoded_ptr[output_length]=in_ptr[i];
      output_length++;
    } else if (in_ptr[i] == ' ') {  // space
      strncpy(encoded_ptr+output_length,(const char*)pl_space_encoding,space_length);
      output_length+=space_length;
    } else { // percent encode
      encoded_ptr[output_length]='%';
      output_length++;
      encoded_ptr[output_length]=c_2_hex[(in_ptr[i] >> 4) & 0xf];
      output_length++;
      encoded_ptr[output_length]=c_2_hex[in_ptr[i] & 0xf];
      output_length++;
    }
  }
  
  CHARSTRING ret_val=CHARSTRING(output_length,encoded_ptr);
  Free(encoded_ptr);
  return ret_val;
}

static int one_digit_dec(const char d){
  if(d>='0' && d<='9'){
    return d-'0';
  } else if(d>='a' && d<='f'){
    return d-'a' +10;
  } else if(d>='A' && d<='F'){
    return d-'A' +10;
  }
  return -1;
}

static int percent_decode_one_char(const char *in, char* out){
  int dc=one_digit_dec(*in);
  if(dc == -1) return 1;
  *out= dc << 4;
  in++;
  dc=one_digit_dec(*in);
  if(dc == -1) return 1;
  *out|= dc;
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f_dec_percent
//
//  Purpose:
//    This function decodes the data into percent encoded string as specified in RFC 3986
//
//  Parameters:
//    pl_pct_data - *charstring* - percent encoded data
//    pl_data - *charstring* - decoded string
//
//  Return Value:
//    *integer* - decoding result: 0 - OK, 1 - decoding failed.
//
///////////////////////////////////////////////////////////////////////////////
INTEGER f__dec__percent(const CHARSTRING& pl_pct_data, CHARSTRING&  pl_data ) {
  size_t input_length=pl_pct_data.lengthof();
  if(input_length==0){
    pl_data="";
    return 0;
  }

  const char* in_ptr=(const char*)pl_pct_data;
  char *decoded_ptr=(char *)Malloc(input_length * sizeof(char));
  size_t output_length=0;
  for(size_t i=0; i<input_length; i++){
    switch(in_ptr[i]){
      case '+':  // space
        decoded_ptr[output_length]=' ';
        output_length++;
        break;
      case '%': // percent encoded data
        char decoded_char;
        if(((i+2)>=input_length) || percent_decode_one_char(in_ptr+i+1,&decoded_char) ){
          // something is wrong
          Free(decoded_ptr);
          return 1;
        }
        decoded_ptr[output_length]=decoded_char;
        output_length++;
        i+=2;
        break;
      default:
        decoded_ptr[output_length]=in_ptr[i];
        output_length++;
        break;
    }
  }
  pl_data=CHARSTRING(output_length,decoded_ptr);
  Free(decoded_ptr);
  return 0;
}


}//namespace
