package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.ldif.LDIFModifyDNChangeRecord;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyModifyDNRequest
       extends ReadOnlyLDAPRequest
{

  String getDN();

  String getNewRDN();

  boolean deleteOldRDN();

  String getNewSuperiorDN();

  ModifyDNRequest duplicate();

  ModifyDNRequest duplicate(final Control[] controls);


  LDIFModifyDNChangeRecord toLDIFChangeRecord();


  String[] toLDIF();

  String toLDIFString();
}
