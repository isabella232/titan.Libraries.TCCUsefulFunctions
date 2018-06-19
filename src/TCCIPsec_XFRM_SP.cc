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
//  File:               TCCIPsec_XFRM_SP.cc
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

void f_process_additionalInfo(
  xfrm_userpolicy_info* pol,
  const SPAdditionalInfo& info
){
  if(info.share().ispresent()){pol->share = info.share()();};
  if(info.priority().ispresent()){pol->priority = info.priority()();};
  if(info.policy__action().ispresent()){pol->action = info.policy__action()();};
  if(info.index().ispresent()){pol->index = info.index()();};
  if(info.interface__index().ispresent()){pol->sel.ifindex = info.interface__index()();};

  if(info.limits().ispresent()){
    Limits limits = info.limits();
    if(limits.soft__byte__limit().ispresent()){pol->lft.soft_byte_limit = limits.soft__byte__limit()();};
    if(limits.hard__byte__limit().ispresent()){pol->lft.hard_byte_limit = limits.hard__byte__limit()();};
    if(limits.soft__packet__limit().ispresent()){pol->lft.soft_packet_limit = limits.soft__packet__limit()();};
    if(limits.hard__packet__limit().ispresent()){pol->lft.hard_packet_limit = limits.hard__packet__limit()();};
    if(limits.soft__add__expires__seconds().ispresent()){pol->lft.soft_add_expires_seconds = limits.soft__add__expires__seconds()();};
    if(limits.hard__add__expires__seconds().ispresent()){pol->lft.hard_add_expires_seconds = limits.hard__add__expires__seconds()();};
  };

  return;
}

void f_add_template(
  xfrm_user_tmpl* xTmpl,
  const Template tmpl,
  int share,
  bool ipv4
){
  if(tmpl.dst().ispresent()){
    f_set_IP_address(tmpl.dst()().ip__address(), &xTmpl->id.daddr);
  }else{
    if(ipv4){
      inet_pton(AF_INET,"0.0.0.0",(void*)&xTmpl->id.daddr.a4);
    }else{
      inet_pton(AF_INET6,"00:00:00:00:00:00:00:00",(void*)&xTmpl->id.daddr.a6);
    };
  };

  if(tmpl.src().ispresent()){
    f_set_IP_address(tmpl.src()().ip__address(), &xTmpl->saddr);
  }else{
    if(ipv4){
      inet_pton(AF_INET,"0.0.0.0",(void*)&xTmpl->saddr.a4);
    }else{
      inet_pton(AF_INET6,"00:00:00:00:00:00:00:00",(void*)&xTmpl->saddr.a6);
    };
  };

   xTmpl->id.spi = htonl(tmpl.spi().get_long_long_val());
   xTmpl->id.proto = tmpl.ipsec();

   if(ipv4)xTmpl->family = AF_INET;
  else xTmpl->family = AF_INET6;

  if(tmpl.reqid().ispresent())xTmpl->reqid  =  tmpl.reqid()().get_long_long_val();
  else xTmpl->reqid = 0;  //0:require else:unique

   xTmpl->mode = tmpl.mode();

   if(tmpl.share().ispresent()){
     xTmpl->share = tmpl.share()();
   } else xTmpl->share = share;

   xTmpl->optional = 0;
   switch(tmpl.level()){
     case Level::use:{xTmpl->optional = 1;break;}
     default:        {xTmpl->optional = 0;}      //Level -- 0:required 1:use
   };

   xTmpl->aalgos = (~(__u32)0);
   xTmpl->ealgos = (~(__u32)0);
   xTmpl->calgos = (~(__u32)0);
  return;
}

void f_set_SP_add_info(
  void* memo,
  const SPAddInfo& pol_info
){
  struct xfrm_userpolicy_info* pol;
  struct xfrm_user_tmpl* tmpl = NULL;
  struct nlattr* ahdr;
  bool ipv4 = true;
  int numberOfTmpls = pol_info.tmpl().size_of();

  pol = (struct xfrm_userpolicy_info*)NLMSG_DATA(memo);
  memset(pol,0,sizeof(struct xfrm_userpolicy_info));

  int addr_family = f_set_IP_address(pol_info.dst().ip__address(), &pol->sel.daddr);
   if(addr_family >= 0){
    pol->sel.family = addr_family;
    if(addr_family == AF_INET){
      pol->sel.prefixlen_d = 32;
      ipv4 = true;
    } else {
      pol->sel.prefixlen_d = 128;
      ipv4 = false;
    };
  }; //else default value will be set: 0.0.0.0

  addr_family = f_set_IP_address(pol_info.src().ip__address(), &pol->sel.saddr);
   if(addr_family >= 0){
    pol->sel.family = addr_family;
    if(addr_family == AF_INET){
      pol->sel.prefixlen_s = 32;
    } else {
      pol->sel.prefixlen_s = 128;
    };
  }; //else default value will be set: 0.0.0.0

  if(pol_info.dst().address__prefix().ispresent()){pol->sel.prefixlen_d = pol_info.dst().address__prefix()();};
   if(pol_info.src().address__prefix().ispresent()){pol->sel.prefixlen_s = pol_info.src().address__prefix()();};
   if(pol_info.dst().port__number().ispresent()){
     pol->sel.dport = htons(pol_info.dst().port__number()());
     pol->sel.dport_mask = 0xffff;
   };
   if(pol_info.src().port__number().ispresent()){
     pol->sel.sport = htons(pol_info.src().port__number()());
     pol->sel.sport_mask = 0xffff;
   };

   pol->sel.ifindex = 0;
   pol->sel.user = 0;

  if(pol_info.protocol() != TransportProtocol::ANY){
    pol->sel.proto = pol_info.protocol();
  } else {
    //in case of ANY, no value should be defined
  }

  //Setting default lifetime values
  pol->lft.soft_byte_limit = XFRM_INF;
   pol->lft.hard_byte_limit = XFRM_INF;
   pol->lft.soft_packet_limit = XFRM_INF;
   pol->lft.hard_packet_limit = XFRM_INF;
   pol->lft.soft_add_expires_seconds = 0;
   pol->lft.hard_add_expires_seconds = 0;
   pol->lft.soft_use_expires_seconds = 0;
   pol->lft.hard_use_expires_seconds = 0;

  pol->curlft.bytes = 0;
   pol->curlft.packets = 0;
   pol->curlft.add_time = 0;
   pol->curlft.use_time = 0;

   pol->index = 0;

   pol->share = XFRM_SHARE_ANY;
   pol->priority = 0;
  pol->action = XFRM_POLICY_ALLOW;
   pol->flags = 0;

   pol->dir  =  pol_info.dir();

  if(pol_info.info().ispresent()){
    f_process_additionalInfo(pol, pol_info.info()());
  };

  Template__List list = pol_info.tmpl();

  ahdr = (struct nlattr*)((char*)pol+NLA_ALIGN(sizeof(*pol)));
  ahdr->nla_len = NLA_HDRLEN+sizeof(*tmpl)*numberOfTmpls;
   ahdr->nla_type = XFRMA_TMPL;

  for(int i = 0;i<numberOfTmpls;i++){
    TTCN_Logger::log( TTCN_DEBUG,"######   %d. template:",i+1);
    if(i>0){
       tmpl = (struct xfrm_user_tmpl*)((char*)tmpl+NLA_ALIGN(sizeof(*tmpl)));
    } else {
       tmpl = (struct xfrm_user_tmpl*)((char*)ahdr+NLA_HDRLEN);
    };

    f_add_template(tmpl,list[i],pol->share,ipv4);
  };
   return;
}

void f_set_SP_delete_info(
  void* memo,
  const SPDelInfo& pol_info
){
  struct xfrm_userpolicy_id* pol;
  int temp;

  pol = (struct xfrm_userpolicy_id*)NLMSG_DATA(memo);
  memset(pol,0,sizeof(struct xfrm_userpolicy_id));

  int addr_family = f_set_IP_address(pol_info.dst().ip__address(), &pol->sel.daddr);
   if(addr_family >= 0){
    pol->sel.family = addr_family;
    if(addr_family == AF_INET){
      pol->sel.prefixlen_d = 32;
    } else {
      pol->sel.prefixlen_d = 128;
    };
  }; //else default value will be set: 0.0.0.0


  temp = inet_pton(AF_INET,pol_info.src().ip__address(),(void*)&pol->sel.saddr.a4);
  if(temp > 0){
    pol->sel.family = AF_INET;
    pol->sel.prefixlen_s = 32;
  }else{
    temp = inet_pton(AF_INET6,pol_info.src().ip__address(),(void*)&pol->sel.saddr.a6);
    if(temp > 0){
      pol->sel.family = AF_INET6;
      pol->sel.prefixlen_s = 128;
    }else{
      TTCN_Logger::log( TTCN_DEBUG,"######   src: "+pol_info.dst().ip__address()+" is not a well-formed IP address!");
    };
  };

  if(pol_info.dst().address__prefix().ispresent()){pol->sel.prefixlen_d = pol_info.dst().address__prefix()();};
   if(pol_info.src().address__prefix().ispresent()){pol->sel.prefixlen_s = pol_info.src().address__prefix()();};

  if(pol_info.dst().port__number().ispresent()){
    pol->sel.dport = htons(pol_info.dst().port__number()());
    pol->sel.dport_mask = 0xffff;
  };

  if(pol_info.src().port__number().ispresent()){
    pol->sel.sport = htons(pol_info.src().port__number()());
    pol->sel.sport_mask = 0xffff;
  };

  pol->sel.proto = pol_info.protocol();
  pol->dir = pol_info.dir();
}

