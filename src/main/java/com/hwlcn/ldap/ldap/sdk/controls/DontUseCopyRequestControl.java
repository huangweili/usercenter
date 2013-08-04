
package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DontUseCopyRequestControl
       extends Control
{

  public static final String DONT_USE_COPY_REQUEST_OID = "1.3.6.1.1.22";

  private static final long serialVersionUID = -5352797941017941217L;

  public DontUseCopyRequestControl()
  {
    super(DONT_USE_COPY_REQUEST_OID, true, null);
  }

  public DontUseCopyRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DONT_USE_COPY_HAS_VALUE.get());
    }
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_DONT_USE_COPY.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DontUseCopyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
