package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionSpecificationRequestControl
       extends Control
{

  public static final String TRANSACTION_SPECIFICATION_REQUEST_OID =
       "1.3.6.1.1.21.2";

  private static final long serialVersionUID = 6489819774149849092L;
  private final ASN1OctetString transactionID;

  static
  {
    final StartTransactionExtendedRequest r = null;
  }



  public TransactionSpecificationRequestControl(
              final ASN1OctetString transactionID)
  {
    super(TRANSACTION_SPECIFICATION_REQUEST_OID, true,
         new ASN1OctetString(transactionID.getValue()));

    ensureNotNull(transactionID);
    this.transactionID = transactionID;
  }

  public TransactionSpecificationRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    transactionID = control.getValue();
    if (transactionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_REQUEST_CONTROL_NO_VALUE.get());
    }
  }

  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_TXN_SPECIFICATION_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("TransactionSpecificationRequestControl(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("')");
  }
}
