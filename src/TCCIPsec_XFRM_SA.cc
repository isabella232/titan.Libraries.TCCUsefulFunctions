///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2017 Ericsson Telecom AB
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCIPsec_XFRM_SA.cc
//  Description:        TCC Useful Functions: IPsec XFRM Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#ifdef LINUX
  #include <linux/netlink.h>
#else
  #include <net/netlink.h>
#endif

#include "TCCIPsec_XFRM_Definitions.hh"
#include "TCCIPsec_XFRM.hh"
#include "Logger.hh"

using namespace TCCIPsec__XFRM__Definitions;

//Sets the IP address to the addr parameter and returns the address family
int f_set_IP_address(CHARSTRING address, xfrm_address_t* addr){
  int temp = inet_pton(AF_INET,address,(void*)&addr->a4);
  if(temp > 0){
    return AF_INET;
  }else{
    temp = inet_pton(AF_INET6,address,(void*)&addr->a6);
    if(temp > 0){
      return AF_INET6;
    }else{
      TTCN_Logger::log( TTCN_DEBUG,"######   dst: "+address+" is not a well-formed IP address!");
      return -1;
    };
  };
}

xfrm_lifetime_cfg f_set_IP_lifetime(Limits limits){
  //Set default values
  xfrm_lifetime_cfg lft;
  lft.soft_byte_limit = XFRM_INF;
  lft.hard_byte_limit = XFRM_INF;
  lft.soft_packet_limit = XFRM_INF;
  lft.hard_packet_limit = XFRM_INF;
  lft.soft_add_expires_seconds = 0;
  lft.hard_add_expires_seconds = 0;
  lft.soft_use_expires_seconds = 0;
  lft.hard_use_expires_seconds = 0;

  if(limits.soft__byte__limit().ispresent()){
    lft.soft_byte_limit = limits.soft__byte__limit()();
  };
   if(limits.hard__byte__limit().ispresent()){
     lft.hard_byte_limit = limits.hard__byte__limit()();
  };
  if(limits.soft__packet__limit().ispresent()){
    lft.soft_packet_limit = limits.soft__packet__limit()();
  };
  if(limits.hard__packet__limit().ispresent()){
    lft.hard_packet_limit = limits.hard__packet__limit()();
  };
  if(limits.soft__add__expires__seconds().ispresent()){
    lft.soft_add_expires_seconds = limits.soft__add__expires__seconds()();
  };
  if(limits.hard__add__expires__seconds().ispresent()){
    lft.hard_add_expires_seconds = limits.hard__add__expires__seconds()();
  };
  if(limits.soft__use__expires__seconds().ispresent()){
    lft.soft_use_expires_seconds = limits.soft__use__expires__seconds()();
  };
  if(limits.hard__use__expires__seconds().ispresent()){
    lft.hard_use_expires_seconds = limits.hard__use__expires__seconds()();
  };
  
  return lft;
}

void f_process_additionalInfo(
  xfrm_usersa_info* sa,
  const SAAdditionalInfo& info
){
  if(info.sel__src().ispresent()){
    f_set_IP_address(info.sel__src()().ip__address(), &sa->sel.saddr);
    if(info.sel__src()().address__prefix().ispresent())sa->sel.prefixlen_s = info.sel__src()().address__prefix()();
    if(info.sel__src()().port__number().ispresent()){
      sa->sel.sport = htons(info.sel__src()().port__number()());
      sa->sel.sport_mask = 0xffff;
    };
  };
  
  if(info.sel__dst().ispresent()){
    f_set_IP_address(info.sel__dst()().ip__address(), &sa->sel.daddr);
    if(info.sel__dst()().address__prefix().ispresent())sa->sel.prefixlen_d = info.sel__dst()().address__prefix()();
    if(info.sel__dst()().port__number().ispresent()){
      sa->sel.dport = htons(info.sel__dst()().port__number()());
      sa->sel.dport_mask = 0xffff;
    };
  };

  if(info.reqid().ispresent()){ sa->reqid  =  info.reqid()().get_long_long_val(); };
  if(info.limits().ispresent()){
    sa->lft = f_set_IP_lifetime(info.limits()());
  };
  return;
}

void f_set_encryptionInfo(
  xfrm_algo* alg,
  const Encryption& info,
  int enc_key_len
){
  bool not_null  =  true;
  switch(info.name()){
    case EncryptionAlgorithms::NULL__ENCR:     {strcpy(alg->alg_name,"ecb(cipher_null)");alg->alg_key_len = 0;memcpy(alg->alg_key,"",0);not_null = false;break;}
    case EncryptionAlgorithms::CBC__AES:       {strcpy(alg->alg_name,"cbc(aes)");break;}
    case EncryptionAlgorithms::CBC__DES:       {strcpy(alg->alg_name,"cbc(des)");break;}
    case EncryptionAlgorithms::CBC__3DES:     {strcpy(alg->alg_name,"cbc(des3_ede)");break;}
    case EncryptionAlgorithms::CBC__CAST5:     {strcpy(alg->alg_name,"cbc(cast5)");break;}
    case EncryptionAlgorithms::CBC__BLOWFISH: {strcpy(alg->alg_name,"cbc(blowfish)");break;}
    case EncryptionAlgorithms::CBC__SERPENT:   {strcpy(alg->alg_name,"cbc(serpent)");break;}
    case EncryptionAlgorithms::CBC__CAMELLIA: {strcpy(alg->alg_name,"cbc(camellia)");break;}
    case EncryptionAlgorithms::CBC__TWOFISH:   {strcpy(alg->alg_name,"cbc(twofish)");break;}
    default: {
      strcpy(alg->alg_name,"ecb(cipher_null)");
      alg -> alg_key_len = 0;
      memcpy(alg->alg_key,"",0);
      not_null = false;
    }
  };
      
  if(not_null){
    alg->alg_key_len = enc_key_len*8;
    if(info.key().get_selection() == IPSecKey::ALT_text){
      memcpy(alg->alg_key,info.key().text(),enc_key_len);
    } else {
      memcpy(alg->alg_key,(const char*)(const unsigned char*)hex2oct(info.key().hex()),enc_key_len);
    };
  };
  return;
}

void f_set_authenticationInfo(
  xfrm_algo* alg,
  const Authentication& info,
  int auth_key_len
){
  bool not_null  =  true;
  switch(info.name()){
    case AuthenticationAlgorithms::NULL__AUTH:     {strcpy(alg->alg_name,"digest_null");alg->alg_key_len = 0;memcpy(alg->alg_key,"",0);not_null = false;break;}
    case AuthenticationAlgorithms::HMAC__MD5:      {strcpy(alg->alg_name,"hmac(md5)");break;}
    case AuthenticationAlgorithms::HMAC__SHA1:    {strcpy(alg->alg_name,"hmac(sha1)");break;}
    case AuthenticationAlgorithms::HMAC__SHA256:  {strcpy(alg->alg_name,"hmac(sha256)");break;}
    case AuthenticationAlgorithms::HMAC__SHA384:  {strcpy(alg->alg_name,"hmac(sha384)");break;}
    case AuthenticationAlgorithms::HMAC__SHA512:   {strcpy(alg->alg_name,"hmac(sha512)");break;}
    case AuthenticationAlgorithms::HMAC__RMD160:  {strcpy(alg->alg_name,"hmac(rmd160)");break;}
    default: {
      strcpy(alg->alg_name,"ecb(cipher_null)");
      alg -> alg_key_len = 0;
      memcpy(alg->alg_key,"",0);
      not_null = false;
    }
  };
  
  if(not_null){
    alg->alg_key_len = auth_key_len*8;
    if(info.key().get_selection() == IPSecKey::ALT_text){
      memcpy(alg->alg_key,info.key().text(),auth_key_len);
    } else {
      memcpy(alg->alg_key,(const char*)(const unsigned char*)hex2oct(info.key().hex()),auth_key_len);
    };
  };
  return;
}

void f_set_MessageBody_for_addSA(
  void* memo,
  const SAAddInfo& sa_info,
  const unsigned int enc_key_len,
  const unsigned int auth_key_len
){
  struct xfrm_usersa_info* sa;
  struct xfrm_algo* alg;
  struct xfrm_encap_tmpl* nat;
  struct nlattr* ahdr = NULL;
  bool multiple_attr = false;

   sa = (struct xfrm_usersa_info*)NLMSG_DATA(memo);
   memset(sa,0,sizeof(struct xfrm_usersa_info));
   
   //set destination address
   int addr_family = f_set_IP_address(sa_info.dst().ip__address(), &sa->id.daddr);
   if(addr_family >= 0){
    sa->family = sa->sel.family = addr_family;
  }; //else default value will be set: 0.0.0.0

  //set source address
  addr_family = f_set_IP_address(sa_info.src().ip__address(), &sa->saddr);
   if(addr_family >= 0){
    sa->family = sa->sel.family = addr_family;
  }; //else default value will be set: 0.0.0.0
   
  sa->sel.prefixlen_d = sa->sel.prefixlen_s = 0;
  
  if(sa_info.protocol() != TransportProtocol::ANY){
    sa->sel.proto = sa_info.protocol();
  } else {
    //in case of ANY no value should be defined
  }

  //Setting default values for each parameter
  //Some of the parameters are not configurable, but can be added later
  sa->sel.ifindex = 0;
  sa->sel.user = 0;
  sa->id.spi = htonl(sa_info.spi().get_long_long_val());
  sa->id.proto = sa_info.ipsec();      
  sa->mode = sa_info.mode();

  sa->curlft.bytes = 0;
  sa->curlft.packets = 0;
  sa->curlft.add_time = 0;
  sa->curlft.use_time = 0;
  sa->stats.replay_window = 0;
  sa->stats.replay = 0;
  sa->stats.integrity_failed = 0;

  sa->seq = 0;
  sa->reqid = 0;
  sa->replay_window = sa->stats.replay_window;
  sa->flags = 0;
    
  if(sa_info.info().ispresent()){
    f_process_additionalInfo(sa, sa_info.info()());
  };
   
  if(sa_info.ipsec__algos().enc().ispresent()){
    TTCN_Logger::log( TTCN_DEBUG,"######   Encryption enabled.");
    ahdr = (struct nlattr*)((char*)sa+NLA_ALIGN(sizeof(*sa)));
    ahdr->nla_len = NLA_HDRLEN+sizeof(struct xfrm_algo)+enc_key_len;
    ahdr->nla_type = XFRMA_ALG_CRYPT;
    alg = (struct xfrm_algo*)((char*)ahdr+NLA_HDRLEN);

    f_set_encryptionInfo(alg, sa_info.ipsec__algos().enc()(),enc_key_len);
    multiple_attr = true;
  };
   
   if(sa_info.ipsec__algos().auth().ispresent()){
    TTCN_Logger::log( TTCN_DEBUG,"######   Authentication enabled.");
     if(multiple_attr){ahdr = (struct nlattr*)((char*)ahdr+NLA_ALIGN(ahdr->nla_len));}
    else {ahdr = (struct nlattr*)((char*)sa+NLA_ALIGN(sizeof(*sa)));};
    ahdr->nla_len = NLA_HDRLEN+sizeof(struct xfrm_algo)+auth_key_len;
    ahdr->nla_type = XFRMA_ALG_AUTH;
    alg = (struct xfrm_algo*)((char*)ahdr+NLA_HDRLEN);

    f_set_authenticationInfo(alg, sa_info.ipsec__algos().auth()(),auth_key_len);
    multiple_attr  =  true;  
   };

  if(sa_info.nat__t().ispresent()){
    TTCN_Logger::log( TTCN_DEBUG,"######   NAT traversal enabled.");
    if(multiple_attr){ahdr = (struct nlattr*)((char*)ahdr+NLA_ALIGN(ahdr->nla_len));}
    else {ahdr = (struct nlattr*)((char*)sa+NLA_ALIGN(sizeof(*sa)));};
    ahdr->nla_len = NLA_HDRLEN+sizeof(*nat);
    ahdr->nla_type = XFRMA_ENCAP;
    nat = (struct xfrm_encap_tmpl*)((char*)ahdr+NLA_HDRLEN);
    
    nat->encap_type = sa_info.nat__t()().encap__type(),
    nat->encap_sport = htons(sa_info.nat__t()().sport());
    nat->encap_dport = htons(sa_info.nat__t()().dport());
    
    if(sa_info.nat__t()().oa().ispresent()){
      addr_family = f_set_IP_address(sa_info.nat__t()().oa()(), &nat->encap_oa);
    };
  };

  return;
}

void f_set_MessageBody_for_deleteSA(
  void* memo,
  const SADelInfo& sa_info
){
  struct xfrm_usersa_id* sa;
  xfrm_address_t* src;
  struct nlattr* ahdr;
  
  sa = (struct xfrm_usersa_id*)NLMSG_DATA(memo);
  memset(sa,0,sizeof(struct xfrm_usersa_id));

  int addr_family = f_set_IP_address(sa_info.dst().ip__address(), &sa->daddr);
   if(addr_family >= 0){
    sa->family = addr_family;
  }; //else default value will be set: 0.0.0.0

  sa->spi = htonl(sa_info.spi().get_long_long_val());

  sa->proto = sa_info.proto();

  ahdr = (struct nlattr*)((char*)sa+NLA_ALIGN(sizeof(*sa)));
  ahdr->nla_len = NLA_HDRLEN+sizeof(*src);
  ahdr->nla_type = XFRMA_SRCADDR;
  src = (xfrm_address_t*)((char*)ahdr+NLA_HDRLEN);
    
  addr_family = f_set_IP_address(sa_info.src().ip__address(), src);

  return;
}
