package com.hwlcn.ldap.ldap.sdk.experimental;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class provides an implementation of the LDAP no-op control as defined in
 * draft-zeilenga-ldap-noop-12.  This control may be included in an add, delete,
 * modify, or modify DN request to indicate that the server should validate the
 * request but not actually make any changes to the data.  It allows the client
 * to verify that the operation would likely succeed (including schema
 * validation, access control checks, and other processing) without making any
 * changes to the server data.
 * <BR><BR>
 * Note that an operation which includes the no-op control will never have a
 * {@link ResultCode#SUCCESS} result.  Instead, if the operation would likely
 * have completed successfully if the no-op control had not been included, then
 * the server will include a response with the {@link ResultCode#NO_OPERATION}
 * result.  If the operation would not have been successful, then the result
 * code in the response will be the appropriate result code for that failure.
 * Note that if the response from the server includes the
 * {@link ResultCode#NO_OPERATION} result, then the LDAP SDK will not throw an
 * exception but will instead return the response in an
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPResult} object.  There is no corresponding
 * response control.
 * <BR><BR>
 * Note that at the time this control was written, the latest version of the
 * specification may be found in draft-zeilenga-ldap-noop-11.  This version of
 * the document does not explicitly specify either the OID that should be used
 * for the control, or the result code that should be used for the associated
 * operation if all other processing is completed successfully but no changes
 * are made as a result of this control.  Until such time as these are defined,
 * this implementation uses the OID temporarily assigned for its use by the
 * OpenLDAP Foundation, which is used by at least the OpenLDAP, OpenDS, and the
 * UnboundID Directory Server implementations.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for attempting to perform a
 * modify operation including the LDAP no-op control so that the change is not
 * actually applied:
 * <PRE>
 *   ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
 *        new Modification(ModificationType.REPLACE, "description",
 *                         "new value"))
 *   modifyRequest.addControl(new NoOpRequestControl());
 *
 *   try
 *   {
 *     LDAPResult result = connection.modify(modifyRequest);
 *     if (result.getResultCode() == ResultCode.NO_OPERATION)
 *     {
 *       System.out.println("The modify would likely have succeeded.");
 *     }
 *     else
 *     {
 *       System.err.println("The modify would have failed.");
 *     }
 *   }
 *   catch (LDAPException le)
 *   {
 *     System.err.println("The modify would have failed.");
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftZeilengaLDAPNoOp12RequestControl
       extends Control
{

  public static final String NO_OP_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.10.2";

  private static final long serialVersionUID = -7435407787971958294L;


  public DraftZeilengaLDAPNoOp12RequestControl()
  {
    super(NO_OP_REQUEST_OID, true, null);
  }


  public DraftZeilengaLDAPNoOp12RequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NOOP_REQUEST_HAS_VALUE.get());
    }
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_NOOP_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("NoOpRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
