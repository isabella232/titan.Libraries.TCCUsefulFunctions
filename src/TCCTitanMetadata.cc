/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCTitanMetadata.cc
//  Description:        TCC Useful Functions: TitanMetadata Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCTitanMetadata_Functions.hh"

namespace TCCTitanMetadata__Functions {

static CHARSTRING compilationtime = __DATE__" " __TIME__;

///////////////////////////////////////////////////////////////////////////////
//  Function: f__compilationTime
// 
//  Purpose:
//    Return the compilation time of module
//
//  Parameters:
//    -
// 
//  Return Value:
//    charstring - compilation time
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__compilationTime()
{
  return compilationtime;
}

} // end of namespace
