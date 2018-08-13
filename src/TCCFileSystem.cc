/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCFileSystem.cc
//  Description:        TCC Useful Functions: FileSystem Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCFileSystem_Functions.hh"
#include <sys/statvfs.h>

namespace TCCFileSystem__Functions
{

INTEGER f__FS__bsize(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER (buffer.f_bsize);
  }
  else{return INTEGER (-1);}
}

INTEGER f__FS__block(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_blocks);
  }
  else{return INTEGER (-1);}
}

INTEGER f__FS__bfree(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_bavail);
  }
  else{return INTEGER (-1);}
}


INTEGER f__FS__dspacerate(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_bavail*100/buffer.f_blocks);
  }
  else{return INTEGER (-1);}
}

}
