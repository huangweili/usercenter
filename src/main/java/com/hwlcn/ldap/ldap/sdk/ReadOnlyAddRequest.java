package com.hwlcn.ldap.ldap.sdk;



import java.util.List;

import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldif.LDIFAddChangeRecord;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyAddRequest
       extends ReadOnlyLDAPRequest
{

  String getDN();


  List<Attribute> getAttributes();


  Attribute getAttribute(final String attributeName);


  boolean hasAttribute(final String attributeName);


  boolean hasAttribute(final Attribute attribute);


  boolean hasAttributeValue(final String attributeName,
                            final String attributeValue);

  boolean hasAttributeValue(final String attributeName,
                            final String attributeValue,
                            final MatchingRule matchingRule);


  boolean hasAttributeValue(final String attributeName,
                            final byte[] attributeValue);



  boolean hasAttributeValue(final String attributeName,
                            final byte[] attributeValue,
                            final MatchingRule matchingRule);

  boolean hasObjectClass(final String objectClassName);



  Entry toEntry();


  AddRequest duplicate();


  AddRequest duplicate(final Control[] controls);


  LDIFAddChangeRecord toLDIFChangeRecord();




  String[] toLDIF();


  String toLDIFString();
}
