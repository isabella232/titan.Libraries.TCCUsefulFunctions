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
//  File:               TCC_JSON.cc
//  Description:        TCC Useful Functions: JSON Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include "TCC_JSON_Functions.hh"
#include "json.hpp"
#include <vector>

using nlohmann::json;
using nlohmann::detail::input_adapter;

namespace TCC__JSON__Functions {


///////////////////////////////////////////////////////////////////////////////
//
// Function: from_unichar
//
// Description:
//   Helper function. Creates a JSON object from a TTCN-3 universal charstring.
//   Multi-byte characters are converted into UTF-8 format.
//
///////////////////////////////////////////////////////////////////////////////
json from_unichar(const UNIVERSAL_CHARSTRING& ustr)
{
  TTCN_Buffer buff;
  ustr.encode_utf8(buff);
  return json::parse(input_adapter(buff.get_data(), buff.get_len()));
}


///////////////////////////////////////////////////////////////////////////////
//
// Function: to_unichar
//
// Description:
//   Helper function. Converts a JSON object to a TTCN-3 universal charstring.
//   The strings in the JSON object are treated as if they were in UTF-8 format.
//   The output format of the JSON document is determined by the module parameters
//   JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING to_unichar(const json& j)
{
  const std::string& j_str = j.dump(JSON__PRETTY__PRINTING,
    JSON__INDENT__CHAR[0].get_char(), JSON__ENSURE__ASCII);
  
  UNIVERSAL_CHARSTRING ret_val;
  ret_val.decode_utf8(j_str.size(), reinterpret_cast<const unsigned char*>(j_str.c_str()));
  return ret_val;
}


///////////////////////////////////////////////////////////////////////////////
//  Function: JSON__to__CBOR
// 
//  Purpose:
//    Converts JSON to CBOR. 
//
//  Parameters:
//    pl__json__str - *in* *universal charstring* - JSON document
// 
//  Return Value:
//    octetstring - resulting CBOR data
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain a valid JSON document.
// 
//  Detailed description:
//    The JSON document is first converted to UTF-8 format.
//    This string is converted to CBOR using the C++ JSON module.
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING JSON__to__CBOR(const UNIVERSAL_CHARSTRING& pl__json__str)
{
  try {
    json j = from_unichar(pl__json__str);
    
    const std::vector<uint8_t>& cbor_bytes = json::to_cbor(j);
    
    return OCTETSTRING(cbor_bytes.size(), cbor_bytes.data());
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting JSON to CBOR: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: CBOR__to__JSON
// 
//  Purpose:
//    Converts CBOR to JSON. 
//
//  Parameters:
//    pl__json__str - *in* *octetstring* - CBOR data
// 
//  Return Value:
//    universal charstring - resulting JSON document
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain valid CBOR data (multi-octet characters must be in UTF-8 format).
// 
//  Detailed description:
//    The CBOR data is first converted to a JSON document in UTF-8 format using
//    the C++ JSON module. This conversion is affected by the module parameters
//    JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//    The JSON document is then converted to a universal charstring.
// 
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING CBOR__to__JSON(const OCTETSTRING& pl__cbor__str)
{
  try {
    json j = json::from_cbor(input_adapter(
      static_cast<const unsigned char*>(pl__cbor__str), pl__cbor__str.lengthof()));
    
    return to_unichar(j);
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting CBOR to JSON: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: JSON__to__MessagePack
// 
//  Purpose:
//    Converts JSON to MessagePack. 
//
//  Parameters:
//    pl__json__str - *in* *universal charstring* - JSON document
// 
//  Return Value:
//    octetstring - resulting MessagePack data
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain a valid JSON document.
// 
//  Detailed description:
//    The JSON document is first converted to UTF-8 format.
//    This string is converted to MessagePack using the C++ JSON module.
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING JSON__to__MessagePack(const UNIVERSAL_CHARSTRING& pl__json__str)
{
  try {
    json j = from_unichar(pl__json__str);
    
    const std::vector<uint8_t>& msgpack_bytes = json::to_msgpack(j);
    
    return OCTETSTRING(msgpack_bytes.size(), msgpack_bytes.data());
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting JSON to MessagePack: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: MessagePack__to__JSON
// 
//  Purpose:
//    Converts MessagePack to JSON. 
//
//  Parameters:
//    pl__json__str - *in* *octetstring* - MessagePack data
// 
//  Return Value:
//    universal charstring - resulting JSON document
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain valid MessagePack data (multi-octet characters must be in UTF-8 format).
// 
//  Detailed description:
//    The MessagePack data is first converted to a JSON document in UTF-8 format using
//    the C++ JSON module. This conversion is affected by the module parameters
//    JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//    The JSON document is then converted to a universal charstring.
// 
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING MessagePack__to__JSON(const OCTETSTRING& pl__msgpack__str)
{
  try {
    json j = json::from_msgpack(input_adapter(
      static_cast<const unsigned char*>(pl__msgpack__str), pl__msgpack__str.lengthof()));
      
    return to_unichar(j);
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting MessagePack to JSON: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: JSON__to__UBJSON
// 
//  Purpose:
//    Converts JSON to UBJSON. 
//
//  Parameters:
//    pl__json__str - *in* *universal charstring* - JSON document
//    pl__use__size - *in* *boolean* - use size annotations for array and object types
//                                     (default: false)
//    pl__use__type - *in* *boolean* - use type annotations for array and object types
//                                     (can only be true if pl_use_size is also true,
//                                     default: false)
// 
//  Return Value:
//    octetstring - resulting UBJSON data
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not contain
//    a valid JSON document, or if pl_use_type is true, but pl_use_size is false.
// 
//  Detailed description:
//    The JSON document is first converted to UTF-8 format.
//    This string is converted to UBJSON using the C++ JSON module, with the
//    size and type annotation settings specified in the parameters.
// 
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING JSON__to__UBJSON(const UNIVERSAL_CHARSTRING& pl__json__str,
                             const BOOLEAN& pl_use_size /* := false */,
                             const BOOLEAN& pl_use_type /* := false */)
{
  if (pl_use_type && !pl_use_size) {
    TTCN_error("Invalid arguments for function JSON_to_UBJSON: "
      "'pl_use_type' can only be set to true if 'pl_use_size' is also true.");
  }

  try {
    json j = from_unichar(pl__json__str);
    
    const std::vector<uint8_t>& ubjson_bytes = json::to_ubjson(j, pl_use_size, pl_use_type);
    
    return OCTETSTRING(ubjson_bytes.size(), ubjson_bytes.data());
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting JSON to UBJSON: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: UBJSON__to__JSON
// 
//  Purpose:
//    Converts UBJSON to JSON. 
//
//  Parameters:
//    pl__json__str - *in* *octetstring* - UBJSON data
// 
//  Return Value:
//    universal charstring - resulting JSON document
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain valid UBJSON data (multi-octet characters must be in UTF-8 format).
// 
//  Detailed description:
//    The UBJSON data is first converted to a JSON document in UTF-8 format using
//    the C++ JSON module. This conversion is affected by the module parameters
//    JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//    The JSON document is then converted to a universal charstring.
// 
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING UBJSON__to__JSON(const OCTETSTRING& pl__ubjson__str)
{
  try {
    json j = json::from_ubjson(input_adapter(
      static_cast<const unsigned char*>(pl__ubjson__str), pl__ubjson__str.lengthof()));
      
    return to_unichar(j);
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While converting UBJSON to JSON: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: flatten__JSON
// 
//  Purpose:
//    Flattens a JSON document. 
//
//  Parameters:
//    pl__json__str - *in* *universal charstring* - input JSON document
// 
//  Return Value:
//    universal charstring - flattened JSON document
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain a valid JSON document.
// 
//  Detailed description:
//    The JSON document is first converted to UTF-8 format.
//    This string is flattened using the C++ JSON module.
//    The format of the flattened string is determined by the module parameters
//    JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//    The JSON document is then converted back to a universal charstring.
// 
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING flatten__JSON(const UNIVERSAL_CHARSTRING& pl__json__str)
{
  try {
    json j_orig = from_unichar(pl__json__str);
    
    json j_flattened = j_orig.flatten();
    
    return to_unichar(j_flattened);
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While flattening JSON value: %s", e.what());
  }
}


///////////////////////////////////////////////////////////////////////////////
//  Function: unflatten__JSON
// 
//  Purpose:
//    Flattens a JSON document. 
//
//  Parameters:
//    pl__json__str - *in* *universal charstring* - flattened JSON document
// 
//  Return Value:
//    universal charstring - unflattened JSON document
//
//  Errors:
//    A dynamic test case error is produced if the first parameter does not
//    contain a valid and flattened JSON document.
// 
//  Detailed description:
//    The JSON document is first converted to UTF-8 format.
//    This string is unflattened using the C++ JSON module.
//    The format of the unflattened string is determined by the module parameters
//    JSON__PRETTY__PRINTING, JSON__INDENT__CHAR and JSON__ENSURE__ASCII.
//    The JSON document is then converted back to a universal charstring.
// 
///////////////////////////////////////////////////////////////////////////////
UNIVERSAL_CHARSTRING unflatten__JSON(const UNIVERSAL_CHARSTRING& pl__json__str)
{
  try {
    json j_orig = from_unichar(pl__json__str);
    
    json j_unflattened = j_orig.unflatten();
    
    return to_unichar(j_unflattened);
  }
  catch (const nlohmann::detail::exception& e) {
    TTCN_error("While unflattening JSON value: %s", e.what());
  }
}

} // end of namespace
