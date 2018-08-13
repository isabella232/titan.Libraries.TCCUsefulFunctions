/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCDateTime.cc
//  Description:        TCC Useful Functions: DateTime Functions
//  Rev:                R36B
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCDateTime_Functions.hh"
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>

namespace TCCDateTime__Functions
{
  const char * TCC_WEEKDAY[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
  const char * TCC_MONTH[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

  //format time string in the following format Www Mmm dd hh:mm::ss.SSS yyyy
  CHARSTRING formatTimeString(const struct tm* ti, int msec)
  {
    char ret_val[30];
    sprintf(ret_val,"%.3s %.3s %.2d %.2d:%.2d:%.2d.%.3d %.4d\n",
        TCC_WEEKDAY[ti->tm_wday], TCC_MONTH[ti->tm_mon], ti->tm_mday,
        ti->tm_hour, ti->tm_min, ti->tm_sec, msec,ti->tm_year + 1900);
    return ret_val;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__time
//
//  Purpose:
//    Current calendar time of the system in seconds
//
//  Parameters:
//    -
//
//  Return Value:
//    integer - time value
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  INTEGER f__time()
  {
    time_t cur_time;
    time( &cur_time );
    INTEGER i;
    i.set_long_long_val(cur_time);
    return i;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__time__ms
//
//  Purpose:
//    Current calendar time of the system in milliseconds
//
//  Parameters:
//    -
//
//  Return Value:
//    integer - time value
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  INTEGER f__time__ms()
  {
    struct timeval ct;
    gettimeofday(&ct,0);
    INTEGER i;
    i.set_long_long_val(ct.tv_sec*1000 + ct.tv_usec/1000);
    return i;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__ctime
//
//  Purpose:
//    Convert a time value in seconds to human readable string.
//    The time represented as local time
//
//  Parameters:
//    pl__sec - *in* *integer* - time value
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__ctime(const INTEGER& pl__sec)
  {
    time_t cur_time = pl__sec.get_long_long_val();
    return ctime(&cur_time);
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__ctime__ms
//
//  Purpose:
//    Convert a time value in milliseconds to human readable string.
//    The time represented as local time
//
//  Parameters:
//    pl__msec - *in* *integer* - time value
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__ctime__ms(const INTEGER& pl__msec)
  {
    time_t ct = pl__msec.get_long_long_val()/1000;
    int msec = pl__msec.get_long_long_val()%1000;
    struct tm * ti = localtime(&ct);
    return  formatTimeString(ti,msec);
  }
///////////////////////////////////////////////////////////////////////////////
//  Function: f__ctime__UTC
//
//  Purpose:
//    Convert a time value in seconds to human readable string.
//    The time represented as UTC
//
//  Parameters:
//    pl__sec - *in* *integer* - time value
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__ctime__UTC(const INTEGER& pl__sec)
  {
      time_t cur_time = pl__sec.get_long_long_val();
      return asctime(gmtime(&cur_time));
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__ctime__ms__UTC
//
//  Purpose:
//    Convert a time value in milliseconds to human readable string.
//    The time represented as UTC
//
//  Parameters:
//    pl__msec - *in* *integer* - time value
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__ctime__ms__UTC(const INTEGER& pl__msec)
  {
    time_t ct = pl__msec.get_long_long_val()/1000;
    int msec = pl__msec.get_long_long_val()%1000;
    struct tm * ti = gmtime(&ct);
    return formatTimeString(ti,msec);
  }



//////////////////////////////////////////////////////////////////////////////
// Function: f__getTpscts
//
// Purpose:
// get special timestamp called Tpscts
// where 18020714540200 = 2018 February 07 14:54:02 GMT+00
//
// Parameters:
//   pl_sec  - *in* *integer* - time value in seconds since epoc or -1
//             if -1 is supplied the current time is used
//   pl_tz   - *in* *integer* - time zone offset in seconds, currently not used
//
// Return Value:
// charstring - tpscts
//
// Errors:
// -
//
// Detailed description:
// -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__getTpscts(const INTEGER& pl__sec, const INTEGER& pl__tz)
  {
  time_t rawtime;
  struct tm *ptm;
  if(pl__sec == -1){
    time(&rawtime);
  } else {
    rawtime = pl__sec.get_long_long_val();
  }
  ptm = gmtime(&rawtime);
  char result[15];
  sprintf(result, "%02d%02d%02d%02d%02d%02d00",
      ptm->tm_year%100,
      ptm->tm_mon+1,
      ptm->tm_mday,
      ptm->tm_hour,
      ptm->tm_min,
      ptm->tm_sec);
  return result;
  }


/*
Semi octet

Each half octet within the field represents one decimal digit. 
The octets with the lowest octet numbers shall contain the most significant decimal digits.
Within one octet, the half octet containing the bits with bit numbers 0 to 3, shall 
represent the most significant digit.

+---------+---------+
| Digit 2 | Digit 1 |
+---------+---------+

if ch == 17 -> return 0x71

*/

unsigned char encode_2_semioctet(unsigned char ch){
  return ((ch % 10) << 4 ) | ( ch / 10 );
}

//////////////////////////////////////////////////////////////////////////////
// Function: f_getOctTpscts
//
// Purpose:
// get special timestamp called TP Service Centre Time Stamp (TP SCTS), 3GPP TS 23.040
// where '81207041452000'O = 2018 February 07 14:54:02 GMT+00
//
// Parameters:
//   pl_sec  - *in* *integer* - time value in seconds since epoc or -1
//             if -1 is supplied the current time is used
//   pl_tz   - *in* *integer* - time zone offset in minutes
//
// Return Value:
// charstring - tpscts
//
// Errors:
// -
//
// Detailed description:
// -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__getOctTpscts(const INTEGER& pl__sec, const INTEGER& pl__tz)
{
  time_t rawtime;
  struct tm *ptm;
  if(pl__sec == -1){
    time(&rawtime);
  } else {
    rawtime = pl__sec.get_long_long_val() + (pl__tz.get_long_long_val() * 60 );
  }
  
  ptm = gmtime(&rawtime);
  
  unsigned char tpscts[7];
  
  tpscts[0] = encode_2_semioctet(ptm->tm_year%100);
  tpscts[1] = encode_2_semioctet(ptm->tm_mon+1);
  tpscts[2] = encode_2_semioctet(ptm->tm_mday);
  tpscts[3] = encode_2_semioctet(ptm->tm_hour);
  tpscts[4] = encode_2_semioctet(ptm->tm_min);
  tpscts[5] = encode_2_semioctet(ptm->tm_sec);
  tpscts[6] = encode_2_semioctet(abs(pl__tz/15));
  if(pl__tz<0){
    tpscts[6] |= 0x08; // set the bit 3 to 1 -> time zoen is negative
  }


  return OCTETSTRING(7, tpscts);
}
  

///////////////////////////////////////////////////////////////////////////////
//  Function: f__getTimeFormatted
//
//  Purpose:
//    Return the current calendar time in a formatted way
//
//  Parameters:
//    pl__sec - *in* *integer* - time value
//    pl__format - *in* *charstring* - format string
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    *Specifier / Replaced by / Example*
//
//    ----------------------------------------------------------------------------------------------------------
//
//    %a - Abbreviated weekday name * - Thu
//
//    %A - Full weekday name * - Thursday
//
//    %b - Abbreviated month name * - Aug
//
//    %B - Full month name * - August
//
//    %c - Date and time representation * - Thu Aug 23 14:55:02 2001
//
//    %d - Day of the month (01-31) - 23
//
//    %H - Hour in 24h format (00-23) - 14
//
//    %I - Hour in 12h format (01-12) - 02
//
//    %j - Day of the year (001-366) - 235
//
//    %m - Month as a decimal number (01-12) - 08
//
//    %M - Minute (00-59) - 55
//
//    %p - AM or PM designation - PM
//
//    %S - Second (00-61) - 02
//
//    %U - Week number with the first Sunday as the first day of week one (00-53) - 33
//
//    %w - Weekday as a decimal number with Sunday as 0 (0-6) - 4
//
//    %W - Week number with the first Monday as the first day of week one (00-53) - 34
//
//    %x - Date representation * - 08/23/01
//
//    %X - Time representation * - 14:55:02
//
//    %y - Year, last two digits (00-99) - 01
//
//    %Y - Year - 2001
//
//    %Z - Timezone name or abbreviation - CDT
//
//    %% - A % sign - %
//
//    ----------------------------------------------------------------------------------------------------------
//
//    * The specifiers whose description is marked with an asterisk (*) are locale-dependent.
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__getTimeFormatted(const INTEGER& pl__sec, const CHARSTRING& pl__format)
  {
    time_t in_time = pl__sec.get_long_long_val();
    size_t str_len = 255;
    char ret_val[str_len];
    strftime (ret_val, str_len, (const char *)pl__format, localtime(&in_time));
    return ret_val;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__time2sec
//
//  Purpose:
//    Function to convert a formated time value to seconds.
//    The time is expressed as local time.
//
//  Parameters:
//    pl__year - *in* *integer* - year (e.g. 2007)
//    pl__mon - *in* *integer* - month (e.g. 3)
//    pl__day - *in* *integer* - day (e.g. 7)
//    pl__hour - *in* *integer* - day (e.g. 12)
//    pl__min - *in* *integer* - day (e.g. 50)
//    pl__sec - *in* *integer* - day (e.g. 7)
//
//  Return Value:
//    integer - time in seconds
//
//  Errors:
//    -
//
//  Detailed description:
//    time in seconds since January 1, 1900
//
///////////////////////////////////////////////////////////////////////////////
  INTEGER f__time2sec(const INTEGER& pl__year,
                      const INTEGER& pl__mon,
                      const INTEGER& pl__mday,
                      const INTEGER& pl__hour,
                      const INTEGER& pl__min,
                      const INTEGER& pl__sec)
  {
    struct tm tms;
    tms.tm_sec = pl__sec;
    tms.tm_min = pl__min;
    tms.tm_hour = pl__hour;
    tms.tm_mday = pl__mday;
    tms.tm_mon = pl__mon - 1;
    tms.tm_year = pl__year - 1900;
    tms.tm_wday = 0;
    tms.tm_yday = 0;
    tms.tm_isdst = -1;

    time_t t = mktime(&tms);
    INTEGER i;
    i.set_long_long_val(t);
    return i;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__time2sec__UTC
//
//  Purpose:
//    Function to convert a formated time value to seconds.
//    The time is expressed as UTC.
//
//  Parameters:
//    pl__year - *in* *integer* - year (e.g. 2007)
//    pl__mon - *in* *integer* - month (e.g. 3)
//    pl__day - *in* *integer* - day (e.g. 7)
//    pl__hour - *in* *integer* - day (e.g. 12)
//    pl__min - *in* *integer* - day (e.g. 50)
//    pl__sec - *in* *integer* - day (e.g. 7)
//
//  Return Value:
//    integer - time in seconds
//
//  Errors:
//    -
//
//  Detailed description:
//    time in seconds since January 1, 1900
//
///////////////////////////////////////////////////////////////////////////////

  INTEGER f__time2sec__UTC(const INTEGER& pl__year,
                           const INTEGER& pl__mon,
                           const INTEGER& pl__mday,
                           const INTEGER& pl__hour,
                           const INTEGER& pl__min,
                           const INTEGER& pl__sec)
  {
    struct tm tms;
    tms.tm_sec = pl__sec;
    tms.tm_min = pl__min;
    tms.tm_hour = pl__hour;
    tms.tm_mday = pl__mday;
    tms.tm_mon = pl__mon - 1;
    tms.tm_year = pl__year - 1900;
    tms.tm_wday = 0;
    tms.tm_yday = 0;
    tms.tm_isdst = 0;

    time_t t = mktime(&tms);
    t-= timezone;

    INTEGER i;
    i.set_long_long_val(t);
    return i;
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__getCurrentDateWithOffset
//
//  Purpose:
//    Generate a date from the actual date and time plus the parameter
//    in seconds e.g. getSdate(30) will return a charstring containing
//    the date and time of 30 seconds later
//
//  Parameters:
//    pl__sec - *in* *integer* - offset time value
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__getCurrentDateWithOffset(const INTEGER& pl__sec)
  {
    time_t cur_time;
    time( &cur_time );
    cur_time += pl__sec.get_long_long_val();
    return ctime (&cur_time);
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__getCurrentGMTDate
//
//  Purpose:
//    Return the current GMT date in format RFC 1123-Date
//    e.g.:Mon Nov 20 11:22:08 2017
//
//  Parameters:
//    -
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__getCurrentGMTDate()
  {
    time_t cur_time;
    time( &cur_time );
    return asctime( gmtime( &cur_time ) );
  }

///////////////////////////////////////////////////////////////////////////////
//  Function: f__getCurrentGMTDate__ms
//
//  Purpose:
//    Return the current GMT date in format Www Mmm dd hh:mm:ss.SSS yyyy
//    e.g.:Mon Nov 20 11:22:08.683 2017
//
//  Parameters:
//    -
//
//  Return Value:
//    charstring - formatted time in string format
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  CHARSTRING f__getCurrentGMTDate__ms()
  {
    struct timeval cur_time;
    gettimeofday(&cur_time,0);
    time_t sec = cur_time.tv_sec;
    int msec = cur_time.tv_usec/1000;
    struct tm * ti = gmtime(&sec);
    return formatTimeString(ti,msec);
  }

//////////////////////////////////////////////////////////////////////////////
//  Function: f__tic
//
//  Purpose:
//    Return the number of clock ticks used by the application since
//    the program was launched
//
//    OR
//
//    Return the amount of CPU time in microseconds since the last call of f__tic
//
//    OR ...
//
//    Warning! This function depends on used library version. Be careful!
//
//  Parameters:
//    -
//
//  Return Value:
//    integer - tics since program start
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  INTEGER f__tic()
  {
    INTEGER i;
    i.set_long_long_val(clock());
    return i;
  }

//////////////////////////////////////////////////////////////////////////////
//  Function: f__toc
//
//  Purpose:
//    Elapsed seconds since time t (only when f__tic() returns the number of
//    clock ticks elapsed since the program was launched)
//
//    Warning! This function depends on used library version. Be careful!
//
//  Parameters:
//    t - *in* *integer* - time value
//
//  Return Value:
//    float - elapsed seconds
//
//  Errors:
//    -
//
//  Detailed description:
//    f__tic counts clock tics since program start. f__toc counts seconds
//    since clock() readout in t till current time
//
///////////////////////////////////////////////////////////////////////////////
  FLOAT f__toc(const INTEGER& t)
  {
    clock_t tt = (clock_t)t.get_long_long_val();
    return FLOAT((double)(clock()-tt)/CLOCKS_PER_SEC);
  }

//////////////////////////////////////////////////////////////////////////////
//  Function: f__timeDiff
//
//  Purpose:
//    Difference between two time
//
//  Parameters:
//    t_start - *in* *integer* - start time
//    t_stop - *in* *integer* - stop time
//
//  Return Value:
//    integer - t_stop-t_start
//
//  Errors:
//    -
//
//  Detailed description:
//    -
//
///////////////////////////////////////////////////////////////////////////////
  INTEGER f__timeDiff(const INTEGER& t_stop, const INTEGER& t_start)
  {
    if(!t_stop.is_bound())
    {
      TTCN_error("Stop time is unbound in call to function TimeDiff");
    }
    if(!t_start.is_bound())
    {
      TTCN_error("Start time is unbound in call to function TimeDiff");
    }
    return t_stop-t_start;
  }

} // end of Namespace
