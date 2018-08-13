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
//  File:               TCCIPsec_XFRM.hh
//  Description:        TCC Useful Functions: IPsec XFRM Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCIPsec_XFRM_Definitions.hh"
#ifdef LINUX
  #include <linux/xfrm.h>
#else
  #include <net/xfrm.h>
#endif

using namespace TCCIPsec__XFRM__Definitions;

void f_set_MessageBody_for_addSA(void*,const SAAddInfo&,const unsigned int,const unsigned int);
void f_set_MessageBody_for_deleteSA(void*,const SADelInfo&);

void f_set_SP_add_info(void*,const SPAddInfo&);
void f_set_SP_delete_info(void*,const SPDelInfo&);

int f_set_IP_address(CHARSTRING, xfrm_address_t*);
xfrm_lifetime_cfg f_set_IP_lifetime(Limits limits);
