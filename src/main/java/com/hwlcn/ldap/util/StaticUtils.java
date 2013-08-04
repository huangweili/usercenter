package com.hwlcn.ldap.util;



import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.UUID;

import com.hwlcn.HwlcnException;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.ldap.sdk.Control;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.UtilityMessages.*;
import static com.hwlcn.ldap.util.Validator.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StaticUtils
{

  public static final byte[] NO_BYTES = new byte[0];


  public static final Control[] NO_CONTROLS = new Control[0];

  public static final String[] NO_STRINGS = new String[0];

  public static final String EOL = System.getProperty("line.separator");

  public static final byte[] EOL_BYTES = getBytes(EOL);

  private static final ThreadLocal<SimpleDateFormat> dateFormatters =
       new ThreadLocal<SimpleDateFormat>();


  private StaticUtils()
  {
  }


  public static byte[] getBytes(final String s)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return NO_BYTES;
    }

    final byte[] b = new byte[length];
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (c <= 0x7F)
      {
        b[i] = (byte) (c & 0x7F);
      }
      else
      {
        try
        {
          return s.getBytes("UTF-8");
        }
        catch (Exception e)
        {
          debugException(e);
          return s.getBytes();
        }
      }
    }

    return b;
  }




  public static boolean isASCIIString(final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }
    }

    return true;
  }



  public static boolean isPrintableString(final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }

      if (((by >= 'a') && (by <= 'z')) ||
          ((by >= 'A') && (by <= 'Z')) ||
          ((by >= '0') && (by <= '9')))
      {
        continue;
      }

      switch (by)
      {
        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '-':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':
        case ' ':
          continue;
        default:
          return false;
      }
    }

    return true;
  }



  public static String toUTF8String(final byte[] b)
  {
    try
    {
      return new String(b, "UTF-8");
    }
    catch (Exception e)
    {
      debugException(e);
      return new String(b);
    }
  }



  public static String toUTF8String(final byte[] b, final int offset,
                                    final int length)
  {
    try
    {
      return new String(b, offset, length, "UTF-8");
    }
    catch (Exception e)
    {

      debugException(e);
      return new String(b, offset, length);
    }
  }


  public static String toInitialLowerCase(final String s)
  {
    if ((s == null) || (s.length() == 0))
    {
      return s;
    }
    else if (s.length() == 1)
    {
      return toLowerCase(s);
    }
    else
    {
      final char c = s.charAt(0);
      if (((c >= 'A') && (c <= 'Z')) || (c < ' ') || (c > '~'))
      {
        final StringBuilder b = new StringBuilder(s);
        b.setCharAt(0, Character.toLowerCase(c));
        return b.toString();
      }
      else
      {
        return s;
      }
    }
  }


  public static String toLowerCase(final String s)
  {
    if (s == null)
    {
      return null;
    }

    final int length = s.length();
    final char[] charArray = s.toCharArray();
    for (int i=0; i < length; i++)
    {
      switch (charArray[i])
      {
        case 'A':
          charArray[i] = 'a';
          break;
        case 'B':
          charArray[i] = 'b';
          break;
        case 'C':
          charArray[i] = 'c';
          break;
        case 'D':
          charArray[i] = 'd';
          break;
        case 'E':
          charArray[i] = 'e';
          break;
        case 'F':
          charArray[i] = 'f';
          break;
        case 'G':
          charArray[i] = 'g';
          break;
        case 'H':
          charArray[i] = 'h';
          break;
        case 'I':
          charArray[i] = 'i';
          break;
        case 'J':
          charArray[i] = 'j';
          break;
        case 'K':
          charArray[i] = 'k';
          break;
        case 'L':
          charArray[i] = 'l';
          break;
        case 'M':
          charArray[i] = 'm';
          break;
        case 'N':
          charArray[i] = 'n';
          break;
        case 'O':
          charArray[i] = 'o';
          break;
        case 'P':
          charArray[i] = 'p';
          break;
        case 'Q':
          charArray[i] = 'q';
          break;
        case 'R':
          charArray[i] = 'r';
          break;
        case 'S':
          charArray[i] = 's';
          break;
        case 'T':
          charArray[i] = 't';
          break;
        case 'U':
          charArray[i] = 'u';
          break;
        case 'V':
          charArray[i] = 'v';
          break;
        case 'W':
          charArray[i] = 'w';
          break;
        case 'X':
          charArray[i] = 'x';
          break;
        case 'Y':
          charArray[i] = 'y';
          break;
        case 'Z':
          charArray[i] = 'z';
          break;
        default:
          if (charArray[i] > 0x7F)
          {
            return s.toLowerCase();
          }
          break;
      }
    }

    return new String(charArray);
  }



  public static boolean isHex(final char c)
  {
    switch (c)
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
      case 'a':
      case 'A':
      case 'b':
      case 'B':
      case 'c':
      case 'C':
      case 'd':
      case 'D':
      case 'e':
      case 'E':
      case 'f':
      case 'F':
        return true;

      default:
        return false;
    }
  }



  public static String toHex(final byte b)
  {
    final StringBuilder buffer = new StringBuilder(2);
    toHex(b, buffer);
    return buffer.toString();
  }



  public static void toHex(final byte b, final StringBuilder buffer)
  {
    switch (b & 0xF0)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x10:
        buffer.append('1');
        break;
      case 0x20:
        buffer.append('2');
        break;
      case 0x30:
        buffer.append('3');
        break;
      case 0x40:
        buffer.append('4');
        break;
      case 0x50:
        buffer.append('5');
        break;
      case 0x60:
        buffer.append('6');
        break;
      case 0x70:
        buffer.append('7');
        break;
      case 0x80:
        buffer.append('8');
        break;
      case 0x90:
        buffer.append('9');
        break;
      case 0xA0:
        buffer.append('a');
        break;
      case 0xB0:
        buffer.append('b');
        break;
      case 0xC0:
        buffer.append('c');
        break;
      case 0xD0:
        buffer.append('d');
        break;
      case 0xE0:
        buffer.append('e');
        break;
      case 0xF0:
        buffer.append('f');
        break;
    }

    switch (b & 0x0F)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x01:
        buffer.append('1');
        break;
      case 0x02:
        buffer.append('2');
        break;
      case 0x03:
        buffer.append('3');
        break;
      case 0x04:
        buffer.append('4');
        break;
      case 0x05:
        buffer.append('5');
        break;
      case 0x06:
        buffer.append('6');
        break;
      case 0x07:
        buffer.append('7');
        break;
      case 0x08:
        buffer.append('8');
        break;
      case 0x09:
        buffer.append('9');
        break;
      case 0x0A:
        buffer.append('a');
        break;
      case 0x0B:
        buffer.append('b');
        break;
      case 0x0C:
        buffer.append('c');
        break;
      case 0x0D:
        buffer.append('d');
        break;
      case 0x0E:
        buffer.append('e');
        break;
      case 0x0F:
        buffer.append('f');
        break;
    }
  }



  public static String toHex(final byte[] b)
  {
    ensureNotNull(b);

    final StringBuilder buffer = new StringBuilder(2 * b.length);
    toHex(b, buffer);
    return buffer.toString();
  }



  public static void toHex(final byte[] b, final StringBuilder buffer)
  {
    toHex(b, null, buffer);
  }



  public static void toHex(final byte[] b, final String delimiter,
                           final StringBuilder buffer)
  {
    boolean first = true;
    for (final byte bt : b)
    {
      if (first)
      {
        first = false;
      }
      else if (delimiter != null)
      {
        buffer.append(delimiter);
      }

      toHex(bt, buffer);
    }
  }



  public static String toHexPlusASCII(final byte[] array, final int indent)
  {
    final StringBuilder buffer = new StringBuilder();
    toHexPlusASCII(array, indent, buffer);
    return buffer.toString();
  }



  public static void toHexPlusASCII(final byte[] array, final int indent,
                                    final StringBuilder buffer)
  {
    if ((array == null) || (array.length == 0))
    {
      return;
    }

    for (int i=0; i < indent; i++)
    {
      buffer.append(' ');
    }

    int pos = 0;
    int startPos = 0;
    while (pos < array.length)
    {
      toHex(array[pos++], buffer);
      buffer.append(' ');

      if ((pos % 16) == 0)
      {
        buffer.append("  ");
        for (int i=startPos; i < pos; i++)
        {
          if ((array[i] < ' ') || (array[i] > '~'))
          {
            buffer.append(' ');
          }
          else
          {
            buffer.append((char) array[i]);
          }
        }
        buffer.append(EOL);
        startPos = pos;

        if (pos < array.length)
        {
          for (int i=0; i < indent; i++)
          {
            buffer.append(' ');
          }
        }
      }
    }

    if ((array.length % 16) != 0)
    {
      final int missingBytes = (16 - (array.length % 16));
      if (missingBytes > 0)
      {
        for (int i=0; i < missingBytes; i++)
        {
          buffer.append("   ");
        }
        buffer.append("  ");
        for (int i=startPos; i < array.length; i++)
        {
          if ((array[i] < ' ') || (array[i] > '~'))
          {
            buffer.append(' ');
          }
          else
          {
            buffer.append((char) array[i]);
          }
        }
        buffer.append(EOL);
      }
    }
  }


  public static void hexEncode(final char c, final StringBuilder buffer)
  {
    final byte[] charBytes;
    if (c <= 0x7F)
    {
      charBytes = new byte[] { (byte) (c & 0x7F) };
    }
    else
    {
      charBytes = getBytes(String.valueOf(c));
    }

    for (final byte b : charBytes)
    {
      buffer.append('\\');
      toHex(b, buffer);
    }
  }


  public static String getStackTrace(final Throwable t)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(t, buffer);
    return buffer.toString();
  }



  public static void getStackTrace(final Throwable t,
                                   final StringBuilder buffer)
  {
    buffer.append(getUnqualifiedClassName(t.getClass()));
    buffer.append('(');

    final String message = t.getMessage();
    if (message != null)
    {
      buffer.append("message='");
      buffer.append(message);
      buffer.append("', ");
    }

    buffer.append("trace='");
    getStackTrace(t.getStackTrace(), buffer);
    buffer.append('\'');

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      getStackTrace(cause, buffer);
    }
    buffer.append(", revision=");
    buffer.append(')');
  }



  public static String getStackTrace(final StackTraceElement[] elements)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(elements, buffer);
    return buffer.toString();
  }


  public static void getStackTrace(final StackTraceElement[] elements,
                                   final StringBuilder buffer)
  {
    for (int i=0; i < elements.length; i++)
    {
      if (i > 0)
      {
        buffer.append(" / ");
      }

      buffer.append(elements[i].getMethodName());
      buffer.append('(');
      buffer.append(elements[i].getFileName());

      final int lineNumber = elements[i].getLineNumber();
      if (lineNumber > 0)
      {
        buffer.append(':');
        buffer.append(lineNumber);
      }
      buffer.append(')');
    }
  }




  public static String getExceptionMessage(final Throwable t)
  {
    if (t == null)
    {
      return ERR_NO_EXCEPTION.get();
    }

    final StringBuilder buffer = new StringBuilder();
    if (t instanceof LDAPSDKException)
    {
      buffer.append(((LDAPSDKException) t).getExceptionMessage());
    }
    else if (t instanceof HwlcnException)
    {
      buffer.append(((HwlcnException) t).getExceptionMessage());
    }
    if ((t instanceof RuntimeException) || (t instanceof Error))
    {
      return getStackTrace(t);
    }
    else
    {
      buffer.append(String.valueOf(t));
    }

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      buffer.append(" caused by ");
      buffer.append(getExceptionMessage(cause));
    }

    return buffer.toString();
  }



  public static String getUnqualifiedClassName(final Class<?> c)
  {
    final String className     = c.getName();
    final int    lastPeriodPos = className.lastIndexOf('.');

    if (lastPeriodPos > 0)
    {
      return className.substring(lastPeriodPos+1);
    }
    else
    {
      return className;
    }
  }


  public static String encodeGeneralizedTime(final Date d)
  {
    SimpleDateFormat dateFormat = dateFormatters.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      dateFormatters.set(dateFormat);
    }

    return dateFormat.format(d);
  }



  public static Date decodeGeneralizedTime(final String t)
         throws ParseException
  {
    ensureNotNull(t);

    int tzPos;
    final TimeZone tz;
    if (t.endsWith("Z"))
    {
      tz = TimeZone.getTimeZone("UTC");
      tzPos = t.length() - 1;
    }
    else
    {
      tzPos = t.lastIndexOf('-');
      if (tzPos < 0)
      {
        tzPos = t.lastIndexOf('+');
        if (tzPos < 0)
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   0);
        }
      }

      tz = TimeZone.getTimeZone("GMT" + t.substring(tzPos));
      if (tz.getRawOffset() == 0)
      {
        if (! (t.endsWith("+0000") || t.endsWith("-0000")))
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   tzPos);
        }
      }
    }
    final String subSecFormatStr;
    final String trimmedTimestamp;
    int periodPos = t.lastIndexOf('.', tzPos);
    if (periodPos > 0)
    {
      final int subSecondLength = tzPos - periodPos - 1;
      switch (subSecondLength)
      {
        case 0:
          subSecFormatStr  = "";
          trimmedTimestamp = t.substring(0, periodPos);
          break;
        case 1:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+2)) + "00";
          break;
        case 2:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+3)) + '0';
          break;
        default:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, periodPos+4);
          break;
      }
    }
    else
    {
      subSecFormatStr  = "";
      periodPos        = tzPos;
      trimmedTimestamp = t.substring(0, tzPos);
    }

    final String formatStr;
    switch (periodPos)
    {
      case 10:
        formatStr = "yyyyMMddHH" + subSecFormatStr;
        break;
      case 12:
        formatStr = "yyyyMMddHHmm" + subSecFormatStr;
        break;
      case 14:
        formatStr = "yyyyMMddHHmmss" + subSecFormatStr;
        break;
      default:
        throw new ParseException(ERR_GENTIME_CANNOT_PARSE_INVALID_LENGTH.get(t),
                                 periodPos);
    }


    final SimpleDateFormat dateFormat = new SimpleDateFormat(formatStr);
    dateFormat.setTimeZone(tz);
    dateFormat.setLenient(false);
    return dateFormat.parse(trimmedTimestamp);
  }



  public static String trimLeading(final String s)
  {
    ensureNotNull(s);

    int nonSpacePos = 0;
    final int length = s.length();
    while ((nonSpacePos < length) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos++;
    }

    if (nonSpacePos == 0)
    {
      return s;
    }
    else if (nonSpacePos >= length)
    {
      return "";
    }
    else
    {
      return s.substring(nonSpacePos, length);
    }
  }



  public static String trimTrailing(final String s)
  {
    ensureNotNull(s);

    final int lastPos = s.length() - 1;
    int nonSpacePos = lastPos;
    while ((nonSpacePos >= 0) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos--;
    }

    if (nonSpacePos < 0)
    {
      return "";
    }
    else if (nonSpacePos == lastPos)
    {

      return s;
    }
    else
    {
      return s.substring(0, (nonSpacePos+1));
    }
  }



  public static List<String> wrapLine(final String line, final int maxWidth)
  {
    final int breakPos = line.indexOf('\n');
    if (breakPos >= 0)
    {
      final ArrayList<String> lineList = new ArrayList<String>(10);
      final StringTokenizer tokenizer = new StringTokenizer(line, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        lineList.addAll(wrapLine(tokenizer.nextToken(), maxWidth));
      }

      return lineList;
    }

    final int length = line.length();
    if ((maxWidth <= 0) || (length < maxWidth))
    {
      return Arrays.asList(line);
    }


    int wrapPos = maxWidth;
    int lastWrapPos = 0;
    final ArrayList<String> lineList = new ArrayList<String>(5);
    while (true)
    {
      final int spacePos = line.lastIndexOf(' ', wrapPos);
      if (spacePos > lastWrapPos)
      {
        final String s = trimTrailing(line.substring(lastWrapPos, spacePos));

        if (s.length() > 0)
        {
          lineList.add(s);
        }

        wrapPos = spacePos;
      }
      else
      {
        lineList.add(line.substring(lastWrapPos, wrapPos));
      }

      while ((wrapPos < length) && (line.charAt(wrapPos) == ' '))
      {
        wrapPos++;
      }

      lastWrapPos = wrapPos;
      wrapPos += maxWidth;
      if (wrapPos >= length)
      {
        if (lastWrapPos >= length)
        {
          break;
        }
        else
        {
          final String s = trimTrailing(line.substring(lastWrapPos));
          if (s.length() > 0)
          {
            lineList.add(s);
          }
          break;
        }
      }
    }

    return lineList;
  }



  public static String cleanExampleCommandLineArgument(final String s)
  {
    return ExampleCommandLineArgument.getCleanArgument(s).getLocalForm();
  }


  public static String concatenateStrings(final String... a)
  {
    return concatenateStrings(null, null, "  ", null, null, a);
  }



  public static String concatenateStrings(final List<String> l)
  {
    return concatenateStrings(null, null, "  ", null, null, l);
  }


  public static String concatenateStrings(final String beforeList,
                                          final String beforeElement,
                                          final String betweenElements,
                                          final String afterElement,
                                          final String afterList,
                                          final String... a)
  {
    return concatenateStrings(beforeList, beforeElement, betweenElements,
         afterElement, afterList, Arrays.asList(a));
  }



  public static String concatenateStrings(final String beforeList,
                                          final String beforeElement,
                                          final String betweenElements,
                                          final String afterElement,
                                          final String afterList,
                                          final List<String> l)
  {
    ensureNotNull(l);

    final StringBuilder buffer = new StringBuilder();

    if (beforeList != null)
    {
      buffer.append(beforeList);
    }

    final Iterator<String> iterator = l.iterator();
    while (iterator.hasNext())
    {
      if (beforeElement != null)
      {
        buffer.append(beforeElement);
      }

      buffer.append(iterator.next());

      if (afterElement != null)
      {
        buffer.append(afterElement);
      }

      if ((betweenElements != null) && iterator.hasNext())
      {
        buffer.append(betweenElements);
      }
    }

    if (afterList != null)
    {
      buffer.append(afterList);
    }

    return buffer.toString();
  }

  public static String secondsToHumanReadableDuration(final long s)
  {
    return millisToHumanReadableDuration(s * 1000L);
  }



  public static String millisToHumanReadableDuration(final long m)
  {
    final StringBuilder buffer = new StringBuilder();
    long numMillis = m;

    final long numDays = numMillis / 86400000L;
    if (numDays > 0)
    {
      numMillis -= (numDays * 86400000L);
      if (numDays == 1)
      {
        buffer.append(INFO_NUM_DAYS_SINGULAR.get(numDays));
      }
      else
      {
        buffer.append(INFO_NUM_DAYS_PLURAL.get(numDays));
      }
    }

    final long numHours = numMillis / 3600000L;
    if (numHours > 0)
    {
      numMillis -= (numHours * 3600000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numHours == 1)
      {
        buffer.append(INFO_NUM_HOURS_SINGULAR.get(numHours));
      }
      else
      {
        buffer.append(INFO_NUM_HOURS_PLURAL.get(numHours));
      }
    }

    final long numMinutes = numMillis / 60000L;
    if (numMinutes > 0)
    {
      numMillis -= (numMinutes * 60000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numMinutes == 1)
      {
        buffer.append(INFO_NUM_MINUTES_SINGULAR.get(numMinutes));
      }
      else
      {
        buffer.append(INFO_NUM_MINUTES_PLURAL.get(numMinutes));
      }
    }

    if (numMillis == 1000)
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      buffer.append(INFO_NUM_SECONDS_SINGULAR.get(1));
    }
    else if ((numMillis > 0) || (buffer.length() == 0))
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      final long numSeconds = numMillis / 1000L;
      numMillis -= (numSeconds * 1000L);
      if ((numMillis % 1000L) != 0L)
      {
        final double numSecondsDouble = numSeconds + (numMillis / 1000.0);
        final DecimalFormat decimalFormat = new DecimalFormat("0.000");
        buffer.append(INFO_NUM_SECONDS_WITH_DECIMAL.get(
             decimalFormat.format(numSecondsDouble)));
      }
      else
      {
        buffer.append(INFO_NUM_SECONDS_PLURAL.get(numSeconds));
      }
    }

    return buffer.toString();
  }




  public static long nanosToMillis(final long nanos)
  {
    return Math.max(0L, Math.round(nanos / 1000000.0d));
  }



  public static long millisToNanos(final long millis)
  {
    return Math.max(0L, (millis * 1000000L));
  }



  public static boolean isNumericOID(final String s)
  {
    boolean digitRequired = true;
    boolean periodFound   = false;
    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          digitRequired = false;
          break;

        case '.':
          if (digitRequired)
          {
            return false;
          }
          else
          {
            digitRequired = true;
          }
          periodFound = true;
          break;

        default:
          return false;
      }

    }

    return (periodFound && (! digitRequired));
  }


  public static String capitalize(final String s)
  {
    if (s == null)
    {
      return null;
    }

    switch (s.length())
    {
      case 0:
        return s;

      case 1:
        return s.toUpperCase();

      default:
        final char c = s.charAt(0);
        if (Character.isUpperCase(c))
        {
          return s;
        }
        else
        {
          return Character.toUpperCase(c) + s.substring(1);
        }
    }
  }


  public static byte[] encodeUUID(final UUID uuid)
  {
    final byte[] b = new byte[16];

    final long mostSignificantBits  = uuid.getMostSignificantBits();
    b[0]  = (byte) ((mostSignificantBits >> 56) & 0xFF);
    b[1]  = (byte) ((mostSignificantBits >> 48) & 0xFF);
    b[2]  = (byte) ((mostSignificantBits >> 40) & 0xFF);
    b[3]  = (byte) ((mostSignificantBits >> 32) & 0xFF);
    b[4]  = (byte) ((mostSignificantBits >> 24) & 0xFF);
    b[5]  = (byte) ((mostSignificantBits >> 16) & 0xFF);
    b[6]  = (byte) ((mostSignificantBits >> 8) & 0xFF);
    b[7]  = (byte) (mostSignificantBits & 0xFF);

    final long leastSignificantBits = uuid.getLeastSignificantBits();
    b[8]  = (byte) ((leastSignificantBits >> 56) & 0xFF);
    b[9]  = (byte) ((leastSignificantBits >> 48) & 0xFF);
    b[10] = (byte) ((leastSignificantBits >> 40) & 0xFF);
    b[11] = (byte) ((leastSignificantBits >> 32) & 0xFF);
    b[12] = (byte) ((leastSignificantBits >> 24) & 0xFF);
    b[13] = (byte) ((leastSignificantBits >> 16) & 0xFF);
    b[14] = (byte) ((leastSignificantBits >> 8) & 0xFF);
    b[15] = (byte) (leastSignificantBits & 0xFF);

    return b;
  }



  public static UUID decodeUUID(final byte[] b)
         throws ParseException
  {
    if (b.length != 16)
    {
      throw new ParseException(ERR_DECODE_UUID_INVALID_LENGTH.get(toHex(b)), 0);
    }

    long mostSignificantBits = 0L;
    for (int i=0; i < 8; i++)
    {
      mostSignificantBits = (mostSignificantBits << 8) | (b[i] & 0xFF);
    }

    long leastSignificantBits = 0L;
    for (int i=8; i < 16; i++)
    {
      leastSignificantBits = (leastSignificantBits << 8) | (b[i] & 0xFF);
    }

    return new UUID(mostSignificantBits, leastSignificantBits);
  }



  public static boolean isWindows()
  {
    final String osName = toLowerCase(System.getProperty("os.name"));
    return ((osName != null) && osName.contains("windows"));
  }



  public static List<String> toArgumentList(final String s)
         throws ParseException
  {
    if ((s == null) || (s.length() == 0))
    {
      return Collections.emptyList();
    }

    int quoteStartPos = -1;
    boolean inEscape = false;
    final ArrayList<String> argList = new ArrayList<String>();
    final StringBuilder currentArg = new StringBuilder();
    for (int i=0; i < s.length(); i++)
    {
      final char c = s.charAt(i);
      if (inEscape)
      {
        currentArg.append(c);
        inEscape = false;
        continue;
      }

      if (c == '\\')
      {
        inEscape = true;
      }
      else if (c == '"')
      {
        if (quoteStartPos >= 0)
        {
          quoteStartPos = -1;
        }
        else
        {
          quoteStartPos = i;
        }
      }
      else if (c == ' ')
      {
        if (quoteStartPos >= 0)
        {
          currentArg.append(c);
        }
        else if (currentArg.length() > 0)
        {
          argList.add(currentArg.toString());
          currentArg.setLength(0);
        }
      }
      else
      {
        currentArg.append(c);
      }
    }

    if (s.endsWith("\\") && (! s.endsWith("\\\\")))
    {
      throw new ParseException(ERR_ARG_STRING_DANGLING_BACKSLASH.get(),
           (s.length() - 1));
    }

    if (quoteStartPos >= 0)
    {
      throw new ParseException(ERR_ARG_STRING_UNMATCHED_QUOTE.get(
           quoteStartPos), quoteStartPos);
    }

    if (currentArg.length() > 0)
    {
      argList.add(currentArg.toString());
    }

    return Collections.unmodifiableList(argList);
  }




  public static <T> List<T> toList(final T[] array)
  {
    if (array == null)
    {
      return null;
    }

    final ArrayList<T> l = new ArrayList<T>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  public static <T> List<T> toNonNullList(final T[] array)
  {
    if (array == null)
    {
      return new ArrayList<T>(0);
    }

    final ArrayList<T> l = new ArrayList<T>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  public static boolean bothNullOrEqual(final Object o1, final Object o2)
  {
    if (o1 == null)
    {
      return (o2 == null);
    }
    else if (o2 == null)
    {
      return false;
    }

    return o1.equals(o2);
  }



  public static boolean bothNullOrEqualIgnoreCase(final String s1,
                                                  final String s2)
  {
    if (s1 == null)
    {
      return (s2 == null);
    }
    else if (s2 == null)
    {
      return false;
    }

    return s1.equalsIgnoreCase(s2);
  }



  public static boolean stringsEqualIgnoreCaseOrderIndependent(
                             final String[] a1, final String[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equalsIgnoreCase(a2[0]));
    }

    final HashSet<String> s1 = new HashSet<String>(a1.length);
    for (final String s : a1)
    {
      s1.add(toLowerCase(s));
    }

    final HashSet<String> s2 = new HashSet<String>(a2.length);
    for (final String s : a2)
    {
      s2.add(toLowerCase(s));
    }

    return s1.equals(s2);
  }




  public static <T> boolean arraysEqualOrderIndependent(final T[] a1,
                                                        final T[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equals(a2[0]));
    }

    final HashSet<T> s1 = new HashSet<T>(Arrays.asList(a1));
    final HashSet<T> s2 = new HashSet<T>(Arrays.asList(a2));
    return s1.equals(s2);
  }
}
