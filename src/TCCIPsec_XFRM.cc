///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2018 Ericsson Telecom AB
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v2.0
// which accompanies this distribution, and is available at
// https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCIPsec_XFRM.cc
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
#include <unistd.h>
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

class Message{
public: 
  void* memory;
public:
  Message(int size){
    memory  =  Malloc(size);
  }

  ~Message(){
    Free(memory); //so no one forgets to free the allocated memory :)
  }
}; //end of class Message

namespace TCCIPsec__XFRM__Definitions {

XFRM__Result send(int fd, void* msg, int len, unsigned long* spi) {
  struct msghdr smsg;
  struct iovec siov;
  struct sockaddr_nl dest;
  char recvbuf[4096];
  struct msghdr rmsg;
  struct iovec riov;
  struct sockaddr_nl from;
  struct nlmsghdr* hdr;
  int rlen;

  memset(&dest,0,sizeof(dest));
  dest.nl_family = AF_NETLINK;
  smsg.msg_name = (void*)&dest;
  smsg.msg_namelen = sizeof(dest);
  smsg.msg_iov = &siov;
  smsg.msg_iovlen = 1;
  smsg.msg_control = NULL;
  smsg.msg_controllen = 0;
  smsg.msg_flags = 0;
  
  siov.iov_base = msg;
  siov.iov_len = len;

  //Sending message to the kernel
  if(sendmsg(fd,&smsg,0) == -1){
    close(fd);
    return XFRM__Result(-1,"TCCIPsec XFRM: Netlink socket send failed.");
  }

  TTCN_Logger::log( TTCN_DEBUG,"###### Netlink socket sent.");
  //Initializing reciever
  riov.iov_base = recvbuf;
  riov.iov_len = 4096;
  rmsg.msg_name = &from;
  rmsg.msg_namelen = sizeof(from);
  rmsg.msg_iov = &riov;
  rmsg.msg_iovlen = 1;
  rmsg.msg_control = NULL;
  rmsg.msg_controllen = 0;
  rmsg.msg_flags = 0;

  TTCN_Logger::log( TTCN_DEBUG,"###### Receiving results from the kernel:");
  rlen = recvmsg(fd,&rmsg,0);
  if(rlen == -1) {
    close(fd);
    return XFRM__Result(-1,"TCCIPsec XFRM: Error in receiving message from the kernel!"); 
  };

  //Processing response
  //Message Format:
  // <--- nlmsg_total_size(payload)  --->
  // <-- nlmsg_msg_size(payload) ->
  //+----------+- - -+-------------+- - -+-------- - -
  //| nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
  //+----------+- - -+-------------+- - -+-------- - -
  //nlmsg_data(nlh)---^                   ^
  //nlmsg_next(nlh)-----------------------+
  for(hdr = (struct nlmsghdr*)recvbuf; NLMSG_OK(hdr,(unsigned)rlen); hdr = NLMSG_NEXT(hdr,rlen)){
    if(hdr -> nlmsg_type == NLMSG_ERROR){
      struct nlmsgerr* answer = (struct nlmsgerr*)NLMSG_DATA(hdr);
      if(answer -> error == 0){
        TTCN_Logger::log( TTCN_DEBUG,"Operation was successful!");
      } else {
        close(fd);
        return XFRM__Result(-1,strerror(-answer->error));
      };
    } else if(hdr -> nlmsg_type == 16){
      //Allocate SPI answer
      struct xfrm_userspi_info* data = (struct xfrm_userspi_info*)NLMSG_DATA(hdr);
      *spi = (unsigned long)htonl(data->info.id.spi);
    } else {
      close(fd);
      return XFRM__Result(-1, "Unexpected message from kernel! Message type: "+(char)hdr->nlmsg_type);
    };
  };
  close(fd);
  return XFRM__Result(0,"TCCIPsec XFRM: Success!"); 
}

XFRM__Result create_socket(void* memo, unsigned int size, unsigned long* spi){
  int xfd;
  struct sockaddr_nl address;

  //Creating Netlink socket
  xfd = socket(AF_NETLINK,SOCK_DGRAM,NETLINK_XFRM);
  if(xfd == -1){
    return XFRM__Result(-1,"TCCIPsec XFRM: Failed!");
  };
  TTCN_Logger::log( TTCN_DEBUG,"###### Netlink socket created.");

  memset(&address,0,sizeof(address));
  address.nl_family = AF_NETLINK;
  if(bind(xfd,(struct sockaddr*)&address,sizeof(address)) == -1){
    close(xfd);
    return XFRM__Result(-1,"TCCIPsec XFRM: Failed to bind soscket");
  };

  TTCN_Logger::log( TTCN_DEBUG,"###### Sending socket to the kernel:");
  return send(xfd, memo, size, spi);
}

void f_set_MessageHeader(void* memo, const int type, const unsigned int length){
  struct nlmsghdr* hdr;
   hdr = (struct nlmsghdr*)memo;

  //Setting the message headers
  hdr->nlmsg_len = NLMSG_LENGTH(length);
  hdr->nlmsg_type = type;
  hdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
  hdr->nlmsg_seq = 1;
  hdr->nlmsg_pid = 0;
  return;
}

XFRM__Result f__XFRM__add__sa(const SAAddInfo& sa_info){
  unsigned long spi = 0;
  unsigned int enc_key_len = 0;
  unsigned int auth_key_len = 0;
  unsigned int payload_len;
  int size;

  TTCN_Logger::log( TTCN_DEBUG,"###### Adding new SAs to the database:");
  payload_len = NLA_ALIGN(sizeof(struct xfrm_usersa_info));
  //Calculating length of the encryption key
  if(sa_info.ipsec__algos().enc().ispresent()) {
   if(sa_info.ipsec__algos().enc()().key().get_selection() == IPSecKey::ALT_text){
     enc_key_len = sa_info.ipsec__algos().enc()().key().text().lengthof();
   } else {
     enc_key_len = sa_info.ipsec__algos().enc()().key().hex().lengthof()/2;
   };
    payload_len += NLA_HDRLEN+NLA_ALIGN(sizeof(struct xfrm_algo)+enc_key_len);
  };

  //Calculating length of the authentication key 
  if(sa_info.ipsec__algos().auth().ispresent()) {
   if(sa_info.ipsec__algos().auth()().key().get_selection() == IPSecKey::ALT_text)auth_key_len = sa_info.ipsec__algos().auth()().key().text().lengthof();
   else auth_key_len = sa_info.ipsec__algos().auth()().key().hex().lengthof()/2;
    payload_len += NLA_HDRLEN+NLA_ALIGN(sizeof(struct xfrm_algo)+auth_key_len);
  };  
  if(sa_info.nat__t().ispresent()) {
    payload_len += NLA_HDRLEN+NLA_ALIGN(sizeof(struct xfrm_encap_tmpl));
  };
 
  size = NLMSG_SPACE(payload_len);
  Message msg = Message(size);
  int message_type = XFRM_MSG_NEWSA;
  if(sa_info.update().ispresent()){
    if(sa_info.update()())message_type = XFRM_MSG_UPDSA;
  };

  f_set_MessageHeader(msg.memory,message_type,payload_len);
  f_set_MessageBody_for_addSA(msg.memory, sa_info, enc_key_len, auth_key_len);

  return create_socket(msg.memory, size, &spi);
};


XFRM__Result f__XFRM__delete__sa(const SADelInfo& sa_info){
  unsigned long spi = 0;
  unsigned int payload_len;
  int size;
  
  TTCN_Logger::log( TTCN_DEBUG,"###### Deleting SA from the database:");
  payload_len = NLA_ALIGN(sizeof(struct xfrm_usersa_id))
               +NLA_HDRLEN+NLA_ALIGN(sizeof(xfrm_address_t));
               
  size = NLMSG_SPACE(payload_len);
  Message msg = Message(size);
  f_set_MessageHeader(msg.memory,XFRM_MSG_DELSA,payload_len);
  f_set_MessageBody_for_deleteSA(msg.memory, sa_info);
  
  return create_socket(msg.memory, size, &spi);
};

XFRM__Result f__XFRM__flush__sa(){
  unsigned long spi = 0;
  const unsigned int payload_len = NLA_ALIGN(sizeof(struct xfrm_usersa_flush));
  int size = NLMSG_SPACE(payload_len);
  struct xfrm_usersa_flush* sa;
  Message msg = Message(size);

  TTCN_Logger::log( TTCN_DEBUG,"###### Flushing SA database");
  f_set_MessageHeader(msg.memory,XFRM_MSG_FLUSHSA,payload_len);

  sa = (struct xfrm_usersa_flush*)NLMSG_DATA(msg.memory);
  memset(sa,0,sizeof(struct xfrm_usersa_flush));

  return create_socket(msg.memory, size, &spi);
};

XFRM__Result f__XFRM__add__policy(const SPAddInfo& pol_info){
  unsigned long spi = 0;
  unsigned int payload_len;
  int size;
  int numberOfTmpls = pol_info.tmpl().size_of();

  TTCN_Logger::log( TTCN_DEBUG,"###### Adding new policies to the database:");
  payload_len = NLA_ALIGN(sizeof(struct xfrm_userpolicy_info))
                   +(NLA_HDRLEN+NLA_ALIGN(sizeof(struct xfrm_user_tmpl)))*numberOfTmpls;
  size = NLMSG_SPACE(payload_len);

  Message msg = Message(size);
  int message_type = XFRM_MSG_NEWPOLICY;
  if(pol_info.update().ispresent()){
    if(pol_info.update()())message_type = XFRM_MSG_UPDPOLICY;
  };

  f_set_MessageHeader(msg.memory,message_type,payload_len);
  f_set_SP_add_info(msg.memory, pol_info);

  return create_socket(msg.memory, size, &spi);
};

XFRM__Result f__XFRM__delete__policy(const SPDelInfo& pol_info){
  unsigned long spi = 0;
  unsigned int payload_len;
  int size;

  TTCN_Logger::log( TTCN_DEBUG,"###### Deleting policies from the database:");
  payload_len = NLA_ALIGN(sizeof(struct xfrm_userpolicy_id));
  size = NLMSG_SPACE(payload_len);
  Message msg = Message(size);
  
  f_set_MessageHeader(msg.memory,XFRM_MSG_DELPOLICY,payload_len);
  f_set_SP_delete_info(msg.memory, pol_info);

  return create_socket(msg.memory, size, &spi);
};

XFRM__Result f__XFRM__flush__policy(){
    unsigned long spi = 0;
  const unsigned int payload_len = NLA_ALIGN(sizeof(struct xfrm_usersa_flush));
  int size = NLMSG_SPACE(payload_len);
  Message msg = Message(size);
  TTCN_Logger::log( TTCN_DEBUG,"###### Flushing the policy database");
  f_set_MessageHeader(msg.memory,XFRM_MSG_FLUSHPOLICY,payload_len);

  return create_socket(msg.memory, size, &spi);
};

XFRM__Result f__XFRM__allocate__SPI(
  const AllocSPI__Info& info,
  INTEGER& spi
){
  unsigned int payload_len = NLA_ALIGN(sizeof(struct xfrm_userspi_info));
  int size = NLMSG_SPACE(payload_len);
  unsigned long spi_val = 0;

  TTCN_Logger::log( TTCN_DEBUG,"###### Getting a free SPI from the kernel.");
  Message msg = Message(size);
  f_set_MessageHeader(msg.memory,XFRM_MSG_ALLOCSPI,payload_len);


  struct xfrm_userspi_info* sa = (struct xfrm_userspi_info*)NLMSG_DATA(msg.memory);
  memset(sa,0,sizeof(struct xfrm_usersa_info));
   
  //set destination address
  int addr_family = f_set_IP_address(info.dst(), &sa->info.id.daddr);
  if(addr_family >= 0){
    sa->info.family = sa->info.sel.family = addr_family;
  }; //else default value will be set: 0.0.0.0

  //set source address
  addr_family = f_set_IP_address(info.src(), &sa->info.saddr);
   if(addr_family >= 0){
    sa->info.family = sa->info.sel.family = addr_family;
  }; //else default value will be set: 0.0.0.0
   
  sa->info.sel.prefixlen_d = sa->info.sel.prefixlen_s = 0;

  //Setting default values for each parameter
  //Some of the parameters are not configurable, but can be added later
  sa->info.sel.ifindex = 0;
  sa->info.sel.user = 0;
  sa->info.id.spi = 0;
  sa->info.id.proto = info.protocol();      
  sa->info.mode = 0;

  sa->info.curlft.bytes = 0;
  sa->info.curlft.packets = 0;
  sa->info.curlft.add_time = 0;
  sa->info.curlft.use_time = 0;
  sa->info.stats.replay_window = 0;
  sa->info.stats.replay = 0;
  sa->info.stats.integrity_failed = 0;

  sa->info.seq = 0;
  sa->info.reqid = 0;
  sa->info.replay_window = sa->info.stats.replay_window;
  sa->info.flags = 0;
  sa->min = 0;
  sa->max = 4294967294;

  if(info.range().ispresent()){
    sa->min = info.range()().min();
    sa->min = info.range()().max();
  };

  XFRM__Result result = create_socket(msg.memory, size, &spi_val);
  spi.set_long_long_val(spi_val);
  return result;
};

} //namespace
