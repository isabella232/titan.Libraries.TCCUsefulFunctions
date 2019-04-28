/******************************************************************************
* Copyright (c) 2000-2019 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCMaths.cc
//  Description:        TCC Useful Functions: Maths Functions.
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include <TTCN3.hh>
#include <math.h>
#include "TCCMaths_Functions.hh"

using namespace TCCMaths__GenericTypes;
namespace TCCMaths__Functions {

///////////////////////////////////////////////////////////////////////////////
//template for count min or max value of list
///////////////////////////////////////////////////////////////////////////////
template<typename T_list>
T_list f_minmax(const T_list& list, bool min)
{
  T_list toret;
  toret[1] = -1;
  toret[0] = 0;

  int len;
  if(!list.is_bound() or ((len = list.size_of()) == 0))
  {
    return toret;
  }

  toret[0] = list[0];
  toret[1] = 0;

  for(int i=1 ; i<len ; ++i)
  {
    if(min?toret[0] > list[i]:toret[0] < list[i])
    {
      toret[0] = list[i];
      toret[1] = i;
    }
  }
  return toret;
}
///////////////////////////////////////////////////////////////////////////////
//  Function: f__maxIL
//
//  Purpose:
//    Return an IntegerList with the highest number found at index 0 and
//    the index of ilist where it's found at index 1
//
//  Parameters:
//    ilist - *in* <IntegerList> - integer array
//
//  Return Value:
//    <IntegerList> - integer array: { <max>, <max index> }
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
IntegerList f__maxIL(const IntegerList& ilist)
{
  return f_minmax(ilist, false);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__minIL
//
//  Purpose:
//     Return an IntegerList with the lowest number found
//     at index 0 and the index of ilist where it's fond at index
//     1
//
//  Parameters:
//    ilist - *in* <IntegerList> - integer array
//
//  Return Value:
//    <IntegerList> - integer array: { <min>, <min index> }
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
IntegerList f__minIL(const IntegerList& ilist)
{
  return f_minmax(ilist, true);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__maxFL
//
//  Purpose:
//    Return an FloatList with the highest number found
//    at index 0 and the index of flist where it's fond at index
//    1
//
//  Parameters:
//    flist - *in* <FloatList> - integer array
//
//  Return Value:
//    <FloatList> - float array: { <max>, <max index> }
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FloatList f__maxFL(const FloatList& flist)
{
  return f_minmax(flist,false);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__minFL
//
//  Purpose:
//    Return an FloatList with the highest number found
//    at index 0 and the index of flist where it's fond at index
//    1
//
//  Parameters:
//    flist - *in* <FloatList> - integer array
//
//  Return Value:
//    <FloatList> - float array: { <min>, <min index> }
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FloatList f__minFL(const FloatList& flist)
{
  return f_minmax(flist, true);
}
///////////////////////////////////////////////////////////////////////////////
//template for count average value of list
///////////////////////////////////////////////////////////////////////////////
template<typename T_list>
FLOAT f_average(const T_list& list)
{
  int len;
  if(!list.is_bound() or ((len = list.size_of()) == 0))
  {
    return 0.0;
  }

  int i;
  double toret = 0.0;
  for(i=0;i<len;++i)
  {
    toret += (double)list[i];
  }
  return toret/(double)len;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__averageFL
//
//  Purpose:
//    Return the average of flist
//
//  Parameters:
//    flist - *in* <FloatList> - integer array
//
//  Return Value:
//    float - average of float numbers
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__averageFL(const FloatList& flist)
{
  return f_average(flist);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__averageIL
//
//  Purpose:
//    Return the average of ilist
//
//  Parameters:
//    ilist - *in* <IntegerList> - integer array
//
//  Return Value:
//    float - average of integer numbers
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__averageIL(const IntegerList& ilist)
{
  return f_average(ilist);
}
///////////////////////////////////////////////////////////////////////////////
// template for update lists
///////////////////////////////////////////////////////////////////////////////
template<typename T_list>
void f_update(T_list& head, const T_list& tail)
{
  if(!tail.is_bound())
  {
    return;
  }

  unsigned int i, count, len = tail.size_of();
  if(head.is_bound())
  {
    count = (unsigned int)head.size_of();
  } else {
    count = 0;
  }
  head.set_size(count + len);
  for(i=0;i<len;++i)
  {
    head[count] = tail[i];
    ++count;
  }
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__updateFL
//
//  Purpose:
//    Append tail to the end of head (head return as inout)
//
//  Parameters:
//    head - *in* <FloatList> - first part of the float list
//    tail - *in* <FloatList> - second part of the float list
//
//  Return Value:
//    -
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
void f__updateFL(FloatList& head, const FloatList& tail)
{
  f_update(head,tail);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__updateIL
//
//  Purpose:
//     Append tail to the end of head (head return as inout)
//
//  Parameters:
//    head - *in* <IntegerList> - first part of the integer list
//    tail - *in* <IntegerList> - second part of the integer list
//
//  Return Value:
//    -
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
void f__updateIL(IntegerList& head, const IntegerList& tail)
{
  f_update(head,tail);
}
///////////////////////////////////////////////////////////////////////////////
//template for count corrected standard deviation
///////////////////////////////////////////////////////////////////////////////
template<typename T_list>
FLOAT f_std(const T_list& list, const FLOAT& in_u = FLOAT())
{
  int len;
  if(!list.is_bound() or ((len = list.size_of()) < 2))
  {
    return 0.0;
  }

  double u, toret = 0.0;
  if (!in_u.is_bound())
  {
    u = f_average(list);
  } else {
    u = in_u;
  }
  double x;
  for(int i=0;i<len;++i)
  {
    x = (double)list[i]-u;
    toret += x*x;
  }

  return pow(toret/(double)(len-1),0.5);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__stdFL
//
//  Purpose:
//    Return the normalized standard deviation of float list
//    (so the average square distance from the center of elements in the list)
//
//  Parameters:
//    flist - *in* <FloatList> - float list
//
//  Return Value:
//    float - normalized, standard derivate
//
//  Errors:
//    -
//
//  Detailed description:
//    E.g.  list = {2.0, 4.0}
//
//          u = (2.0 + 4.0) / 2 <- *center of elements in the list*
//
//          len = sizeof(list)
//
//          [ ( (2.0-u)^2 + (4.0-u)^2 ) / len ] ^ (0.5)
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__stdFL(const FloatList& flist)
{
  return f_std(flist);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__stdFLL
//
//  Purpose:
//    Return the normalized standard deviation of float list  using custom
//    center
//    (so it is the average square distance from a user defined central value)
//
//  Parameters:
//    u - *in* *float* - user defined central value
//    flist - *in* <FloatList> - float list
//
//  Return Value:
//    float - normalized, standard derivate
//
//  Errors:
//    -
//
//  Detailed description:
//    Note: u is the average value of flist and has to be calculated
//    before a call to this function
//
//    E.g.  list = {2.0, 4.0}
//
//          u <- *user input*
//
//          len = sizeof(list)
//
//          [ ( (2.0-u)^2 + (4.0-u)^2 ) / len ] ^ (0.5)
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__stdFLL(const FloatList& flist, const FLOAT& u)
{
  return f_std(flist,u);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__stdIL
//
//  Purpose:
//    Return the normalized standard deviation of integer list
//    (so the average square distance from the center of points)
//
//  Parameters:
//    ilist - *in* <IntegerList> - integer list
//
//  Return Value:
//    float - normalized, standard derivate
//
//  Errors:
//    -
//
//  Detailed description:
//    E.g.  list = {2.0, 4.0}
//
//          u = (2.0 + 4.0) / 2 <- *center of elements in the list*
//
//          len = sizeof(list)
//
//          [ ( (2.0-u)^2 + (4.0-u)^2 ) / len ] ^ (0.5)
//
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__stdIL(const IntegerList& ilist)
{
  return f_std(ilist);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__stdILL
//
//  Purpose:
//    Return the normalized standard deviation of integer list using custom
//    center
//    (so it is the average square distance from a user defined central value)
//
//  Parameters:
//    u - *in* *float* - user defined central value
//    ilist - *in* <IntegerList> - integer list
//
//  Return Value:
//    float - normalized, standard derivate
//
//  Errors:
//    -
//
//  Detailed description:
//    Note: u is a user defined value
//
//    E.g.  list = {2.0, 4.0}
//
//          u <- *user input*
//
//          len = sizeof(list)
//
//          [ ( (2.0-u)^2 + (4.0-u)^2 ) / len ] ^ (0.5)
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__stdILL(const IntegerList& ilist, const FLOAT& u)
{
  return f_std(ilist,u);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sinVL
//
//  Purpose:
//    Return the values of the sin function
//
//  Parameters:
//    freq - *in* *float* - the frequency of the sine curve
//    altitude - *in* *float* - the altitude of the sine curve
//    start_val - *in* *float* - the starting value passed to the sine function
//    len - *in* *integer* - the wanted number of points of the sine curve
//    step - *in* *float* - the length between the points on the sine curve
//
//  Return Value:
//    <FloatList> - the wanted points in a float list
//
//  Errors:
//    -
//
//  Detailed description:
//    Generation of one sin value:
//
//      altitude * sin(2 * pi * freq * start_val)
//
//      start_val := start_val + step
//
///////////////////////////////////////////////////////////////////////////////
FloatList f__sinVL(const FLOAT& freq, const FLOAT& altitude, const FLOAT& start__val, const INTEGER& len, const FLOAT& step)
{
  int i;
  double tmp = start__val;
  FloatList toret;
  double common = 2.0 * M_PI * freq;
  if (len > 0)
  {
    toret.set_size(len);
    for ( i = 0; i < len; ++i)
    {
      toret[i] = altitude * sin(common * tmp);
      tmp += step;
    }
  }
    return toret;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__cosVL
//
//  Purpose:
//    Return the values of the cos function
//
//  Parameters:
//    freq - *in* *float* - the frequency of the sine curve
//    altitude - *in* *float* - the altitude of the sine curve
//    start_val - *in* *float* - the starting value passed to the sine function
//    len - *in* *integer* - the wanted number of points of the sine curve
//    step - *in* *float* - the length between the points on the sine curve
//
//  Return Value:
//    <FloatList> - the wanted points in a float list
//
//  Errors:
//    -
//
//  Detailed description:
//    Generation of one cos value:
//
//      altitude * cos(2 * pi * freq * start_val)
//
//      start_val := start_val + step
//
///////////////////////////////////////////////////////////////////////////////
FloatList f__cosVL(const FLOAT& freq, const FLOAT& altitude, const FLOAT& start__val, const INTEGER& len, const FLOAT& step)
{
  int i;
  double tmp = start__val;
  FloatList toret;
  double common = 2.0 * M_PI * freq;
  if (len > 0)
  {
    toret.set_size(len);
    for ( i = 0; i < len; ++i)
    {
      toret[i] = altitude * cos(common * tmp);
      tmp += step;
    }
  }
  return toret;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sin
//
//  Purpose:
//    Return the sine of angle radians
//
//  Parameters:
//    angle - *in* *float* - angle in radians
//
//  Return Value:
//    float - the sine value of angle radians
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__sin(const FLOAT& angle)
{
  return sin(angle);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__cos
//
//  Purpose:
//    Return the cosine of angle radians
//
//  Parameters:
//    angle - *in* *float* - angle in radians
//
//  Return Value:
//    float - the cosine value of angle radians
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__cos(const FLOAT& angle)
{
  return cos(angle);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__asin
//
//  Purpose:
//    Return the arc sine of value in [-pi/2, +pi/2]
//
//  Parameters:
//    val - *in* *float* - value
//
//  Return Value:
//    float - the arc sine value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__asin(const FLOAT& val)
{
  return asin(val);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__acos
//
//  Purpose:
//    Return the arc cosine of value in [0, pi]
//
//  Parameters:
//    val - *in* *float* - value
//
//  Return Value:
//    float - the arc cosine value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__acos(const FLOAT& val)
{
  return acos(val);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__powFF
//
//  Purpose:
//    Raise to power (float to float power)
//
//  Parameters:
//    base - *in* *float* - base value
//    expo - *in* *float* - exponent value
//
//  Return Value:
//    float - base raised to power expo
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__powFF(const FLOAT& base, const FLOAT& expo)
{
  return pow(base, expo);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__powII
//
//  Purpose:
//    Raise to power (integer to integer power)
//
//  Parameters:
//    base - *in* *integer* - base value
//    expo - *in* *integer* - exponent value
//
//  Return Value:
//    integer - base raised to power expo
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
INTEGER f__powII(const INTEGER& base, const INTEGER& expo)
{
  return float2int(pow(int2float(base), int2float(expo)));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__powIF
//
//  Purpose:
//    Raise to power (integer to float power)
//
//  Parameters:
//    base - *in* *integer* - base value
//    expo - *in* *float* - exponent value
//
//  Return Value:
//    float - base raised to power expo
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__powIF(const INTEGER& base, const FLOAT& expo)
{
  return pow(int2float(base), expo);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__powFI
//
//  Purpose:
//    Raise to power (float to integer power)
//
//  Parameters:
//    base - *in* *float* - base value
//    expo - *in* *integer* - exponent value
//
//  Return Value:
//    float - base raised to power expo
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__powFI(const FLOAT& base, const INTEGER& expo)
{
  return pow(base, int2float(expo));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sqrF
//
//  Purpose:
//    Raise a float value to square
//
//  Parameters:
//    base - *in* *float* - base value
//
//  Return Value:
//    float - square of base
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__sqrF(const FLOAT& base)
{
  return base*base;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sqrI
//
//  Purpose:
//    Raise an integer value to square
//
//  Parameters:
//    base - *in* *integer* - base value
//
//  Return Value:
//    integer - square of base
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
INTEGER f__sqrI(const INTEGER& base)
{
  return base*base;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sqrtF
//
//  Purpose:
//    Square root of float value
//
//  Parameters:
//    base - *in* *float* - base value
//
//  Return Value:
//    float - square root of base
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__sqrtF(const FLOAT& base)
{
  return sqrt(base);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__sqrtI
//
//  Purpose:
//    Square root of integer value
//
//  Parameters:
//    base - *in* *integer* - base value
//
//  Return Value:
//    float - square root of base
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__sqrtI(const INTEGER& base)
{
  return sqrt(int2float(base));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__ceil
//
//  Purpose:
//    Return the smallest integer value that is not less then value
//
//  Parameters:
//    val - *in* *float* - float value
//
//  Return Value:
//    integer - ceil value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
INTEGER f__ceil(const FLOAT& val)
{
  return float2int(ceil(val));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__floor
//
//  Purpose:
//    Return the largest integer value that is not greater then value
//
//  Parameters:
//    val - *in* *float* - float value
//
//  Return Value:
//    integer - floor value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
INTEGER f__floor(const FLOAT& val)
{
  return float2int(floor(val));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__exp
//
//  Purpose:
//    Return the exponential value of the argument
//
//  Parameters:
//    val - *in* *float* - float value
//
//  Return Value:
//    float - exp value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__exp(const FLOAT& val)
{
  return exp(val);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__log
//
//  Purpose:
//    Return the natural logarithm of the argument
//
//  Parameters:
//    val - *in* *float* - float value
//
//  Return Value:
//    float - ln value of val
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
FLOAT f__log(const FLOAT& val)
{
  return log(val);
}

}
