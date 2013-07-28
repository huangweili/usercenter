
package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DisconnectType
{

  UNBIND(INFO_DISCONNECT_TYPE_UNBIND.get(), ResultCode.LOCAL_ERROR),



  BIND_FAILED(INFO_DISCONNECT_TYPE_BIND_FAILED.get(),
       ResultCode.CONNECT_ERROR),

  RECONNECT(INFO_DISCONNECT_TYPE_RECONNECT.get(), ResultCode.SERVER_DOWN),


  REFERRAL(INFO_DISCONNECT_TYPE_REFERRAL.get(), ResultCode.LOCAL_ERROR),



  SERVER_CLOSED_WITH_NOTICE(
       INFO_DISCONNECT_TYPE_SERVER_CLOSED_WITH_NOTICE.get(),
       ResultCode.SERVER_DOWN),


  SERVER_CLOSED_WITHOUT_NOTICE(
       INFO_DISCONNECT_TYPE_SERVER_CLOSED_WITHOUT_NOTICE.get(),
       ResultCode.SERVER_DOWN),


  IO_ERROR(INFO_DISCONNECT_TYPE_IO_ERROR.get(), ResultCode.SERVER_DOWN),


  DECODE_ERROR(INFO_DISCONNECT_TYPE_DECODE_ERROR.get(),
       ResultCode.DECODING_ERROR),



  LOCAL_ERROR(INFO_DISCONNECT_TYPE_LOCAL_ERROR.get(), ResultCode.LOCAL_ERROR),



  SECURITY_PROBLEM(INFO_DISCONNECT_TYPE_SECURITY_PROBLEM.get(),
       ResultCode.LOCAL_ERROR),



  POOL_CLOSED(INFO_DISCONNECT_TYPE_POOL_CLOSED.get(), ResultCode.LOCAL_ERROR),


  POOL_CREATION_FAILURE(INFO_DISCONNECT_TYPE_POOL_CREATION_FAILURE.get(),
       ResultCode.CONNECT_ERROR),



  POOLED_CONNECTION_DEFUNCT(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_DEFUNCT.get(),
       ResultCode.SERVER_DOWN),



  POOLED_CONNECTION_EXPIRED(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_EXPIRED.get(),
       ResultCode.LOCAL_ERROR),


  POOLED_CONNECTION_UNNEEDED(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_UNNEEDED.get(),
       ResultCode.LOCAL_ERROR),


  UNKNOWN(INFO_DISCONNECT_TYPE_UNKNOWN.get(), ResultCode.LOCAL_ERROR),




  CLOSED_BY_FINALIZER(INFO_DISCONNECT_TYPE_CLOSED_BY_FINALIZER.get(),
       ResultCode.LOCAL_ERROR),



  OTHER(INFO_DISCONNECT_TYPE_OTHER.get(), ResultCode.LOCAL_ERROR);



  private final ResultCode resultCode;


  private final String description;




  private DisconnectType(final String description, final ResultCode resultCode)
  {
    this.description = description;
    this.resultCode  = resultCode;
  }




  public String getDescription()
  {
    return description;
  }




  public ResultCode getResultCode()
  {
    return resultCode;
  }




  public static DisconnectType forName(final String name)
  {
    final String lowerName = toLowerCase(name);
    if (lowerName.equals("unbind"))
    {
      return UNBIND;
    }
    else if (lowerName.equals("bind_failed"))
    {
      return BIND_FAILED;
    }
    else if (lowerName.equals("reconnect"))
    {
      return RECONNECT;
    }
    else if (lowerName.equals("referral"))
    {
      return REFERRAL;
    }
    else if (lowerName.equals("server_closed_with_notice"))
    {
      return SERVER_CLOSED_WITH_NOTICE;
    }
    else if (lowerName.equals("server_closed_without_notice"))
    {
      return SERVER_CLOSED_WITHOUT_NOTICE;
    }
    else if (lowerName.equals("io_error"))
    {
      return IO_ERROR;
    }
    else if (lowerName.equals("decode_error"))
    {
      return DECODE_ERROR;
    }
    else if (lowerName.equals("local_error"))
    {
      return LOCAL_ERROR;
    }
    else if (lowerName.equals("security_problem"))
    {
      return SECURITY_PROBLEM;
    }
    else if (lowerName.equals("pool_closed"))
    {
      return POOL_CLOSED;
    }
    else if (lowerName.equals("pool_creation_failure"))
    {
      return POOL_CREATION_FAILURE;
    }
    else if (lowerName.equals("pooled_connection_defunct"))
    {
      return POOLED_CONNECTION_DEFUNCT;
    }
    else if (lowerName.equals("pooled_connection_expired"))
    {
      return POOLED_CONNECTION_EXPIRED;
    }
    else if (lowerName.equals("pooled_connection_unneeded"))
    {
      return POOLED_CONNECTION_UNNEEDED;
    }
    else if (lowerName.equals("unknown"))
    {
      return UNKNOWN;
    }
    else if (lowerName.equals("closed_by_finalizer"))
    {
      return CLOSED_BY_FINALIZER;
    }
    else if (lowerName.equals("other"))
    {
      return OTHER;
    }

    return null;
  }




  public static boolean isExpected(final DisconnectType disconnectType)
  {
    switch (disconnectType)
    {
      case UNBIND:
      case RECONNECT:
      case REFERRAL:
      case POOL_CLOSED:
      case POOLED_CONNECTION_DEFUNCT:
      case POOLED_CONNECTION_EXPIRED:
      case POOLED_CONNECTION_UNNEEDED:
      case CLOSED_BY_FINALIZER:
        return true;
      default:
        return false;
    }
  }



  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  public void toString(final StringBuilder buffer)
  {
    buffer.append("DisconnectType(name='");
    buffer.append(name());
    buffer.append("', resultCode='");
    buffer.append(resultCode);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("')");
  }
}
