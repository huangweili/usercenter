package com.hwlcn.ldap.ldif;



import java.io.Serializable;

import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFRecord
       extends Serializable
{

  String getDN();


  DN getParsedDN()
     throws LDAPException;


  String[] toLDIF();




  String[] toLDIF(final int wrapColumn);


  void toLDIF(final ByteStringBuffer buffer);

  void toLDIF(final ByteStringBuffer buffer, final int wrapColumn);


  String toLDIFString();


  String toLDIFString(final int wrapColumn);



  void toLDIFString(final StringBuilder buffer);

  void toLDIFString(final StringBuilder buffer, final int wrapColumn);


  @Override()
  String toString();

  void toString(final StringBuilder buffer);
}
