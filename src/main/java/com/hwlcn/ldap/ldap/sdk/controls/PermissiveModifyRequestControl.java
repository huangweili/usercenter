package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the permissive modify request
 * control, which is supported by a number of servers and may be included in a
 * modify request to indicate that the server should not reject a modify
 * request which attempts to add an attribute value which already exists or
 * remove an attribute value which does not exist.  Normally, such modification
 * attempts would be rejected.
 * <BR><BR>
 * The OID for this control is "1.2.840.113556.1.4.1413".  It does not have a
 * value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the permissive modify request
 * control to remove a value of "test" from the description attribute, or to do
 * nothing if that value is not contained in the entry.
 * <PRE>
 *   Modification mod = new Modification(ModificationType.DELETE,
 *        "description", "test");
 *   ModifyRequest modifyRequest = new ModifyRequest(
 *        "uid=john.doe,ou=People,dc=example,dc=com", mod);
 *   modifyRequest.addControl(new PermissiveModifyRequestControl());
 *   LDAPResult modifyResult = connection.modify(modifyRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PermissiveModifyRequestControl
       extends Control
{
  public static final String PERMISSIVE_MODIFY_REQUEST_OID =
       "1.2.840.113556.1.4.1413";

  private static final long serialVersionUID = -2599039772002106760L;

  public PermissiveModifyRequestControl()
  {
    super(PERMISSIVE_MODIFY_REQUEST_OID, false, null);
  }

  public PermissiveModifyRequestControl(final boolean isCritical)
  {
    super(PERMISSIVE_MODIFY_REQUEST_OID, isCritical, null);
  }

  public PermissiveModifyRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PERMISSIVE_MODIFY_HAS_VALUE.get());
    }
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PERMISSIVE_MODIFY_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PermissiveModifyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
