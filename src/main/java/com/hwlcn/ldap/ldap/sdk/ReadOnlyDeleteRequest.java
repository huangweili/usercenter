package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.ldif.LDIFDeleteChangeRecord;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyDeleteRequest
       extends ReadOnlyLDAPRequest
{

  String getDN();

  DeleteRequest duplicate();

  DeleteRequest duplicate(final Control[] controls);

  LDIFDeleteChangeRecord toLDIFChangeRecord();

  String[] toLDIF();

  String toLDIFString();
}
