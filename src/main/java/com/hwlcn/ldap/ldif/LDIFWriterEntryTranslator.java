package com.hwlcn.ldap.ldif;



import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFWriterEntryTranslator
{

  Entry translateEntryToWrite(Entry original);
}
