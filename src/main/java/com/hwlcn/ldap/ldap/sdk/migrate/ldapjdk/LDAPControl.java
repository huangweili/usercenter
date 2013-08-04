package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.controls.ManageDsaITRequestControl;
import com.hwlcn.ldap.ldap.sdk.controls.PasswordExpiredControl;
import com.hwlcn.ldap.ldap.sdk.controls.PasswordExpiringControl;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPControl
       implements Serializable
{
  public static final String MANAGEDSAIT =
       ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID;

  public static final String PWEXPIRED =
       PasswordExpiredControl.PASSWORD_EXPIRED_OID;


  public static final String PWEXPIRING =
       PasswordExpiringControl.PASSWORD_EXPIRING_OID;

  private static final long serialVersionUID = 7828506470553016637L;


  private final boolean isCritical;

  private final byte[] value;

  private final String oid;

  public LDAPControl(final Control control)
  {
    oid        = control.getOID();
    isCritical = control.isCritical();

    if (control.hasValue())
    {
      value = control.getValue().getValue();
    }
    else
    {
      value = null;
    }
  }


  public LDAPControl(final String id, final boolean critical, final byte[] vals)
  {
    oid        = id;
    isCritical = critical;
    value      = vals;
  }



  public String getID()
  {
    return oid;
  }


  public boolean isCritical()
  {
    return isCritical;
  }


  public byte[] getValue()
  {
    return value;
  }

  public final Control toControl()
  {
    if (value == null)
    {
      return new Control(oid, isCritical, null);
    }
    else
    {
      return new Control(oid, isCritical, new ASN1OctetString(value));
    }
  }

  public static Control[] toControls(final LDAPControl[] ldapControls)
  {
    if (ldapControls == null)
    {
      return null;
    }

    final Control[] controls = new Control[ldapControls.length];
    for (int i=0; i < ldapControls.length; i++)
    {
      controls[i] = ldapControls[i].toControl();
    }

    return controls;
  }


  public static LDAPControl[] toLDAPControls(final Control[] controls)
  {
    if (controls == null)
    {
      return null;
    }

    final LDAPControl[] ldapControls = new LDAPControl[controls.length];
    for (int i=0; i < controls.length; i++)
    {
      ldapControls[i] = new LDAPControl(controls[i]);
    }

    return ldapControls;
  }


  public LDAPControl duplicate()
  {
    return new LDAPControl(oid, isCritical, value);
  }


  @Override()
  public String toString()
  {
    return toControl().toString();
  }
}
