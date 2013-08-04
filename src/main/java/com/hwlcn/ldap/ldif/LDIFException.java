package com.hwlcn.ldap.ldif;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.hwlcn.ldap.util.LDAPSDKException;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFException
       extends LDAPSDKException
{

  private static final long serialVersionUID = 1665883395956836732L;

  private final boolean mayContinueReading;

  private final long lineNumber;

  private final List<String> dataLines;

  public LDIFException(final String message, final long lineNumber,
                       final boolean mayContinueReading)
  {
    this(message, lineNumber, mayContinueReading, (List<CharSequence>) null,
         null);
  }

  public LDIFException(final String message, final long lineNumber,
                       final boolean mayContinueReading, final Throwable cause)
  {
    this(message, lineNumber, mayContinueReading, (List<CharSequence>) null,
         cause);
  }

  public LDIFException(final String message, final long lineNumber,
                       final boolean mayContinueReading,
                       final CharSequence[] dataLines, final Throwable cause)
  {
    this(message, lineNumber, mayContinueReading,
         (dataLines == null) ? null : Arrays.asList(dataLines),
         cause);
  }

  public LDIFException(final String message, final long lineNumber,
                       final boolean mayContinueReading,
                       final List<? extends CharSequence> dataLines,
                       final Throwable cause)
  {
    super(message, cause);

    ensureNotNull(message);

    this.lineNumber         = lineNumber;
    this.mayContinueReading = mayContinueReading;

    if (dataLines == null)
    {
      this.dataLines = null;
    }
    else
    {
      final ArrayList<String> lineList =
           new ArrayList<String>(dataLines.size());
      for (final CharSequence s : dataLines)
      {
        lineList.add(s.toString());
      }

      this.dataLines = Collections.unmodifiableList(lineList);
    }
  }

  public long getLineNumber()
  {
    return lineNumber;
  }

  public boolean mayContinueReading()
  {
    return mayContinueReading;
  }

  public List<String> getDataLines()
  {
    return dataLines;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFException(lineNumber=");
    buffer.append(lineNumber);
    buffer.append(", mayContinueReading=");
    buffer.append(mayContinueReading);
    buffer.append(", message='");
    buffer.append(getMessage());

    if (dataLines != null)
    {
      buffer.append("', dataLines='");
      for (final CharSequence s : dataLines)
      {
        buffer.append(s);
        buffer.append("{end-of-line}");
      }
    }

    final Throwable cause = getCause();
    if (cause == null)
    {
      buffer.append("')");
    }
    else
    {
      buffer.append("', cause=");
      StaticUtils.getStackTrace(cause, buffer);
      buffer.append(')');
    }
  }


  @Override()
  public String getExceptionMessage()
  {
    return toString();
  }
}
