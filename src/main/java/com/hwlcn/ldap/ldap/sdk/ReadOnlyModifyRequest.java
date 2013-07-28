package com.hwlcn.ldap.ldap.sdk;



import java.util.List;

import com.hwlcn.ldap.ldif.LDIFModifyChangeRecord;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyModifyRequest
       extends ReadOnlyLDAPRequest
{

  String getDN();


  List<Modification> getModifications();

  ModifyRequest duplicate();

  ModifyRequest duplicate(final Control[] controls);


  LDIFModifyChangeRecord toLDIFChangeRecord();


  String[] toLDIF();

  String toLDIFString();
}
