package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;

import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPURL;
import com.hwlcn.ldap.ldap.sdk.SearchScope;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;



@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPUrl
       implements Serializable
{

  private static final long serialVersionUID = -1716384037873600695L;

  private final LDAPURL ldapURL;


  public LDAPUrl(final String url)
         throws MalformedURLException
  {
    try
    {
      ldapURL = new LDAPURL(url);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new MalformedURLException(le.getMessage());
    }
  }


  public LDAPUrl(final String host, final int port, final String dn)
         throws RuntimeException
  {
    try
    {
      final DN dnObject = (dn == null) ? null : new DN(dn);
      ldapURL = new LDAPURL("ldap", host, port, dnObject, null, null, null);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new RuntimeException(e);
    }
  }
  public LDAPUrl(final String host, final int port, final String dn,
                 final String[] attributes, final int scope,
                 final String filter)
         throws RuntimeException
  {
    try
    {
      final DN          dnObject     = (dn == null) ? null : new DN(dn);
      final SearchScope scopeObject  = SearchScope.valueOf(scope);
      final Filter      filterObject = Filter.create(filter);
      ldapURL = new LDAPURL("ldap", host, port, dnObject, attributes,
                            scopeObject, filterObject);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new RuntimeException(e);
    }
  }

  public LDAPUrl(final String host, final int port, final String dn,
                 final Enumeration<String> attributes, final int scope,
                 final String filter)
         throws RuntimeException
  {
    try
    {
      final DN          dnObject     = (dn == null) ? null : new DN(dn);
      final SearchScope scopeObject  = SearchScope.valueOf(scope);
      final Filter      filterObject = Filter.create(filter);

      final String[] attrs;
      if (attributes == null)
      {
        attrs = null;
      }
      else
      {
        final ArrayList<String> attrList = new ArrayList<String>();
        while (attributes.hasMoreElements())
        {
          attrList.add(attributes.nextElement());
        }
        attrs = new String[attrList.size()];
        attrList.toArray(attrs);
      }

      ldapURL = new LDAPURL("ldap", host, port, dnObject, attrs, scopeObject,
                            filterObject);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new RuntimeException(e);
    }
  }

  public LDAPUrl(final LDAPURL ldapURL)
  {
    this.ldapURL = ldapURL;
  }


  public String getHost()
  {
    return ldapURL.getHost();
  }


  public int getPort()
  {
    return ldapURL.getPort();
  }


  public String getDN()
  {
    if (ldapURL.baseDNProvided())
    {
      return ldapURL.getBaseDN().toString();
    }
    else
    {
      return null;
    }
  }


  public Enumeration<String> getAttributes()
  {
    final String[] attributes = ldapURL.getAttributes();
    if (attributes.length == 0)
    {
      return null;
    }
    else
    {
      return new IterableEnumeration<String>(Arrays.asList(attributes));
    }
  }


  public String[] getAttributeArray()
  {
    final String[] attributes = ldapURL.getAttributes();
    if (attributes.length == 0)
    {
      return null;
    }
    else
    {
      return attributes;
    }
  }



  public int getScope()
  {
    return ldapURL.getScope().intValue();
  }


  public String getFilter()
  {
    return ldapURL.getFilter().toString();
  }


  @Override()
  public int hashCode()
  {
    return ldapURL.hashCode();
  }


  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o instanceof LDAPUrl)
    {
      return ldapURL.equals(((LDAPUrl) o).ldapURL);
    }

    return false;
  }

  public String getUrl()
  {
    return ldapURL.toString();
  }


  public final LDAPURL toLDAPURL()
  {
    return ldapURL;
  }


  @Override()
  public String toString()
  {
    return ldapURL.toString();
  }
}
