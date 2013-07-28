package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.util.LDAPSDKException;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class EntrySourceException
       extends LDAPSDKException
{

  private static final long serialVersionUID = -9221149707074845318L;

  private final boolean mayContinueReading;


  public EntrySourceException(final boolean mayContinueReading,
                              final Throwable cause)
  {
    super(StaticUtils.getExceptionMessage(cause), cause);

    Validator.ensureNotNull(cause);

    this.mayContinueReading = mayContinueReading;
  }


  public EntrySourceException(final boolean mayContinueReading,
                              final String message, final Throwable cause)
  {
    super(message, cause);

    Validator.ensureNotNull(message, cause);

    this.mayContinueReading = mayContinueReading;
  }


  public final boolean mayContinueReading()
  {
    return mayContinueReading;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EntrySourceException(message='");
    buffer.append(getMessage());
    buffer.append("', mayContinueReading=");
    buffer.append(mayContinueReading);
    buffer.append(", cause='");
    buffer.append(StaticUtils.getExceptionMessage(getCause()));
    buffer.append("')");
  }
}
