package com.hwlcn.ldap.ldap.sdk.persist;



import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPPersistException
       extends LDAPException
{
  private static final long serialVersionUID = 8625904586803506713L;


  private final Object partiallyDecodedObject;


  public LDAPPersistException(final LDAPException e)
  {
    super(e);

    partiallyDecodedObject = null;
  }

  public LDAPPersistException(final String message)
  {
    super(ResultCode.LOCAL_ERROR, message);

    partiallyDecodedObject = null;
  }


  public LDAPPersistException(final String message, final Throwable cause)
  {
    super(ResultCode.LOCAL_ERROR, message, cause);

    partiallyDecodedObject = null;
  }


  public LDAPPersistException(final String message,
                              final Object partiallyDecodedObject,
                              final Throwable cause)
  {
    super(ResultCode.LOCAL_ERROR, message, cause);

    this.partiallyDecodedObject = partiallyDecodedObject;
  }

  public Object getPartiallyDecodedObject()
  {
    return partiallyDecodedObject;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPPersistException(message='");
    buffer.append(getMessage());
    buffer.append('\'');

    if (partiallyDecodedObject != null)
    {
      buffer.append(", partiallyDecodedObject=");
      buffer.append(partiallyDecodedObject);
    }

    final Throwable cause = getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(StaticUtils.getExceptionMessage(cause));
    }

    buffer.append(')');
  }
}
