/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCXPathSupport_Functions.ttcn
//  Description:        TCC Useful Functions: XPath Support Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include <string.h>

#include "tinyxml.h"
#include "xpath_processor.h"

#include "TCCXPathSupport_Functions.hh"


///////////////////////////////////////////////////////////////////////////////
//  Function: XPathQuery
// 
//  Purpose:
//    apply an XPath query on an XML document
// 
//  Parameters:
//    xml_doc: the XML document to be processed. It is modeled by a pure TTCN-3
//                universal charstring and passed as an input parameter to this 
//                function
//
//    xpath_query: the XPath Query. With this technology we can access a node of
//                    the XML tree. It is passed to the function as a universal 
//                    charstring
//  
//  Return Value:
//    universal charstring - result of the query (information about one node of
//                              the XML tree)
// 
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////

namespace TCCXPathSupport__Functions { 

char * extract_string(const UNIVERSAL_CHARSTRING & us)
{
  TTCN_Buffer buf;
  us.encode_utf8(buf);
  
  
  size_t len = buf.get_len();
  char * return_string = (char*) Malloc(len+1);
  memcpy(return_string,buf.get_data(),len);
  return_string[len] = '\0';
  
  return return_string;
}

UNIVERSAL_CHARSTRING XPathQuery(const UNIVERSAL_CHARSTRING& xml__doc, const UNIVERSAL_CHARSTRING& xpath__query)
{
  
	char* xml_document = extract_string( xml__doc );
  char* xpath_query  = extract_string( xpath__query );
  
      
  TiXmlDocument * XDp_doc  = new TiXmlDocument();
  
  XDp_doc->Parse( xml_document );
	  
  TiXmlElement  * XEp_root = XDp_doc->RootElement();
  
  
  
  TinyXPath::xpath_processor *proc = new TinyXPath::xpath_processor( XEp_root, xpath_query );
      
  TIXML_STRING res = proc->S_compute_xpath(); 
  
	
  
  delete XDp_doc;
  delete proc;
  Free(xml_document);
  Free(xpath_query);

  
  UNIVERSAL_CHARSTRING result;
  result.decode_utf8(res.size(),(const unsigned char*)res.c_str());
  return result;

}

BOOLEAN XPathCheckXML(const UNIVERSAL_CHARSTRING& xml__doc, CHARSTRING& error__string){
	char* xml_document = extract_string( xml__doc );
  TiXmlDocument * XDp_doc  = new TiXmlDocument();
  
  XDp_doc->Parse( xml_document );

  bool ret_val= ! XDp_doc->Error();
  if(ret_val){ // no error
    error__string="OK";
  } else { // error
    char * e_str=mprintf("Error at line: %d, pos: %d, description: %s",XDp_doc->ErrorRow(),XDp_doc->ErrorCol(),XDp_doc->ErrorDesc());
    error__string=e_str;
    Free(e_str);
  }
  delete XDp_doc;
  Free(xml_document);
  return ret_val;
}


}
