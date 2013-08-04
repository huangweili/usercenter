package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.AddRequest;
import com.hwlcn.ldap.ldap.sdk.BindResult;
import com.hwlcn.ldap.ldap.sdk.CompareRequest;
import com.hwlcn.ldap.ldap.sdk.CompareResult;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DeleteRequest;
import com.hwlcn.ldap.ldap.sdk.DereferencePolicy;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.InternalSDKHelper;
import com.hwlcn.ldap.ldap.sdk.LDAPConnectionOptions;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModifyDNRequest;
import com.hwlcn.ldap.ldap.sdk.ModifyRequest;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchRequest;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.ldap.ldap.sdk.SearchScope;
import com.hwlcn.ldap.ldap.sdk.SimpleBindRequest;
import com.hwlcn.ldap.ldap.sdk.UpdatableLDAPRequest;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;

@Mutable()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPConnection
{

  public static final int DEREF_NEVER = DereferencePolicy.NEVER.intValue();

  public static final int DEREF_SEARCHING =
       DereferencePolicy.SEARCHING.intValue();

  public static final int DEREF_FINDING =
       DereferencePolicy.FINDING.intValue();

  public static final int DEREF_ALWAYS =
       DereferencePolicy.ALWAYS.intValue();

  public static final int SCOPE_BASE = SearchScope.BASE_INT_VALUE;

  public static final int SCOPE_ONE = SearchScope.ONE_INT_VALUE;

  public static final int SCOPE_SUB = SearchScope.SUB_INT_VALUE;

  private final com.hwlcn.ldap.ldap.sdk.LDAPConnection conn;

  private LDAPConstraints constraints;

  private LDAPControl[] responseControls;

  private LDAPSearchConstraints searchConstraints;

  private LDAPSocketFactory socketFactory;

  private String authDN;

  private String authPW;

  public LDAPConnection()
  {
    this(null);
  }


  public LDAPConnection(final LDAPSocketFactory socketFactory)
  {
    this.socketFactory = socketFactory;
    if (socketFactory == null)
    {
      conn = new com.hwlcn.ldap.ldap.sdk.LDAPConnection();
    }
    else
    {

      conn = new com.hwlcn.ldap.ldap.sdk.LDAPConnection(
           new LDAPToJavaSocketFactory(socketFactory));
    }

    authDN = null;
    authPW = null;

    constraints       = new LDAPConstraints();
    searchConstraints = new LDAPSearchConstraints();
  }


  @Override()
  protected void finalize()
            throws Throwable
  {
    conn.close();

    super.finalize();
  }

  public com.hwlcn.ldap.ldap.sdk.LDAPConnection getSDKConnection()
  {
    return conn;
  }


  public String getHost()
  {
    return conn.getConnectedAddress();
  }


  public int getPort()
  {
    return conn.getConnectedPort();
  }

  public String getAuthenticationDN()
  {
    return authDN;
  }

  public String getAuthenticationPassword()
  {
    return authPW;
  }


  public int getConnectTimeout()
  {
    final int connectTimeoutMillis =
         conn.getConnectionOptions().getConnectTimeoutMillis();
    if (connectTimeoutMillis > 0)
    {
      return Math.max(1, (connectTimeoutMillis / 1000));
    }
    else
    {
      return 0;
    }
  }


  public void setConnectTimeout(final int timeout)
  {
    final LDAPConnectionOptions options = conn.getConnectionOptions();

    if (timeout > 0)
    {
      options.setConnectTimeoutMillis(1000 * timeout);
    }
    else
    {
      options.setConnectTimeoutMillis(0);
    }

    conn.setConnectionOptions(options);
  }

  public LDAPSocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  public void setSocketFactory(final LDAPSocketFactory socketFactory)
  {
    this.socketFactory = socketFactory;

    if (socketFactory == null)
    {
      conn.setSocketFactory(null);
    }
    else
    {
      conn.setSocketFactory(new LDAPToJavaSocketFactory(socketFactory));
    }
  }

  public LDAPConstraints getConstraints()
  {
    return constraints;
  }


  public void setConstraints(final LDAPConstraints constraints)
  {
    if (constraints == null)
    {
      this.constraints = new LDAPConstraints();
    }
    else
    {
      this.constraints = constraints;
    }
  }

  public LDAPSearchConstraints getSearchConstraints()
  {
    return searchConstraints;
  }


  public void setSearchConstraints(
                   final LDAPSearchConstraints searchConstraints)
  {
    if (searchConstraints == null)
    {
      this.searchConstraints = new LDAPSearchConstraints();
    }
    else
    {
      this.searchConstraints = searchConstraints;
    }
  }

  public LDAPControl[] getResponseControls()
  {
    return responseControls;
  }

  public boolean isConnected()
  {
    return conn.isConnected();
  }

  public void connect(final String host, final int port)
         throws LDAPException
  {
    authDN           = null;
    authPW           = null;
    responseControls = null;

    try
    {
      conn.connect(host, port);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      throw new LDAPException(le);
    }
  }


  public void connect(final String host, final int port, final String dn,
                      final String password)
         throws LDAPException
  {
    connect(3, host, port, dn, password, null);
  }

  public void connect(final String host, final int port, final String dn,
                      final String password, final LDAPConstraints constraints)
         throws LDAPException
  {
    connect(3, host, port, dn, password, constraints);
  }



  public void connect(final int version, final String host, final int port,
                      final String dn, final String password)
         throws LDAPException
  {
    connect(version, host, port, dn, password, null);
  }


  public void connect(final int version, final String host, final int port,
                      final String dn, final String password,
                      final LDAPConstraints constraints)
         throws LDAPException
  {
    connect(host, port);

    try
    {
      if ((dn != null) && (password != null))
      {
        bind(version, dn, password, constraints);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
  }


  public void disconnect()
         throws LDAPException
  {
    conn.close();
    authDN = null;
    authPW = null;
  }


  public void reconnect()
         throws LDAPException
  {
    final String host = getHost();
    final int    port = getPort();
    final String dn   = authDN;
    final String pw   = authPW;

    conn.close();

    if ((dn == null) || (pw == null))
    {
      connect(host, port);
    }
    else
    {
      connect(host, port, dn, pw);
    }
  }

  public void abandon(final int id)
         throws LDAPException
  {
    try
    {
      conn.abandon(InternalSDKHelper.createAsyncRequestID(id, conn),
                   getControls(null));
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      throw new LDAPException(le);
    }
  }


  public void add(final LDAPEntry entry)
         throws LDAPException
  {
    add(entry, null);
  }


  public void add(final LDAPEntry entry, final LDAPConstraints constraints)
         throws LDAPException
  {
    final AddRequest addRequest = new AddRequest(entry.toEntry());
    update(addRequest, constraints);

    try
    {
      final LDAPResult result = conn.add(addRequest);
      setResponseControls(result);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  public void authenticate(final String dn, final String password)
         throws LDAPException
  {
    bind(3, dn, password, null);
  }



  public void authenticate(final String dn, final String password,
                           final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(3, dn, password, constraints);
  }



  public void authenticate(final int version, final String dn,
                           final String password)
         throws LDAPException
  {
    bind(version, dn, password, null);
  }


  public void authenticate(final int version, final String dn,
                           final String password,
                           final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(version, dn, password, constraints);
  }


  public void bind(final String dn, final String password)
         throws LDAPException
  {
    bind(3, dn, password, null);
  }


  public void bind(final String dn, final String password,
                   final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(3, dn, password, constraints);
  }


  public void bind(final int version, final String dn, final String password)
         throws LDAPException
  {
    bind(version, dn, password, null);
  }

  public void bind(final int version, final String dn, final String password,
                   final LDAPConstraints constraints)
         throws LDAPException
  {
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(dn, password, getControls(constraints));
    authDN = null;
    authPW = null;

    try
    {
      final BindResult bindResult = conn.bind(bindRequest);
      setResponseControls(bindResult);
      if (bindResult.getResultCode() == ResultCode.SUCCESS)
      {
        authDN = dn;
        authPW = password;
      }
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  public boolean compare(final String dn, final LDAPAttribute attribute)
         throws LDAPException
  {
    return compare(dn, attribute, null);
  }


  public boolean compare(final String dn, final LDAPAttribute attribute,
                         final LDAPConstraints constraints)
         throws LDAPException
  {
    final CompareRequest compareRequest = new CompareRequest(dn,
         attribute.getName(), attribute.getByteValueArray()[0]);
    update(compareRequest, constraints);

    try
    {
      final CompareResult result = conn.compare(compareRequest);
      setResponseControls(result);
      return result.compareMatched();
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }

  public void delete(final String dn)
         throws LDAPException
  {
    delete(dn, null);
  }


  public void delete(final String dn, final LDAPConstraints constraints)
         throws LDAPException
  {
    final DeleteRequest deleteRequest = new DeleteRequest(dn);
    update(deleteRequest, constraints);

    try
    {
      final LDAPResult result = conn.delete(deleteRequest);
      setResponseControls(result);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  public LDAPExtendedOperation extendedOperation(
              final LDAPExtendedOperation extendedOperation)
         throws LDAPException
  {
    return extendedOperation(extendedOperation,  null);
  }


  public LDAPExtendedOperation extendedOperation(
              final LDAPExtendedOperation extendedOperation,
              final LDAPConstraints constraints)
         throws LDAPException
  {
    final ExtendedRequest extendedRequest = new ExtendedRequest(
         extendedOperation.getID(),
         new ASN1OctetString(extendedOperation.getValue()),
         getControls(constraints));

    try
    {
      final ExtendedResult result =
           conn.processExtendedOperation(extendedRequest);
      setResponseControls(result);

      if (result.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPException(result.getDiagnosticMessage(),
             result.getResultCode().intValue(), result.getDiagnosticMessage(),
             result.getMatchedDN());
      }

      final byte[] valueBytes;
      final ASN1OctetString value = result.getValue();
      if (value == null)
      {
        valueBytes = null;
      }
      else
      {
        valueBytes = value.getValue();
      }

      return new LDAPExtendedOperation(result.getOID(), valueBytes);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  public void modify(final String dn, final LDAPModification mod)
         throws LDAPException
  {
    modify(dn, new LDAPModification[] { mod }, null);
  }


  public void modify(final String dn, final LDAPModification[] mods)
         throws LDAPException
  {
    modify(dn, mods, null);
  }



  public void modify(final String dn, final LDAPModification mod,
                     final LDAPConstraints constraints)
         throws LDAPException
  {
    modify(dn, new LDAPModification[] { mod }, constraints);
  }



  public void modify(final String dn, final LDAPModification[] mods,
                     final LDAPConstraints constraints)
         throws LDAPException
  {
    final Modification[] m = new Modification[mods.length];
    for (int i=0; i < mods.length; i++)
    {
      m[i] = mods[i].toModification();
    }

    final ModifyRequest modifyRequest = new ModifyRequest(dn, m);
    update(modifyRequest, constraints);

    try
    {
      final LDAPResult result = conn.modify(modifyRequest);
      setResponseControls(result);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  public void modify(final String dn, final LDAPModificationSet mods)
         throws LDAPException
  {
    modify(dn, mods.toArray(), null);
  }


  public void modify(final String dn, final LDAPModificationSet mods,
                     final LDAPConstraints constraints)
         throws LDAPException
  {
    modify(dn, mods.toArray(), constraints);
  }


  public LDAPEntry read(final String dn)
         throws LDAPException
  {
    return read(dn, null, null);
  }


  public LDAPEntry read(final String dn,
                        final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    return read(dn, null, constraints);
  }


  public LDAPEntry read(final String dn, final String[] attrs)
         throws LDAPException
  {
    return read(dn, attrs, null);
  }


  public LDAPEntry read(final String dn, final String[] attrs,
                        final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    final Filter filter = Filter.createORFilter(
         Filter.createPresenceFilter("objectClass"),
         Filter.createEqualityFilter("objectClass", "ldapSubentry"));

    final SearchRequest searchRequest =
         new SearchRequest(dn, SearchScope.BASE, filter, attrs);
    update(searchRequest, constraints);

    try
    {
      final SearchResult searchResult = conn.search(searchRequest);
      setResponseControls(searchResult);

      if (searchResult.getEntryCount() != 1)
      {
        throw new LDAPException(null, LDAPException.NO_RESULTS_RETURNED);
      }

      return new LDAPEntry(searchResult.getSearchEntries().get(0));
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }

  public void rename(final String dn, final String newRDN,
                     final boolean deleteOldRDN)
         throws LDAPException
  {
    rename(dn, newRDN, null, deleteOldRDN, null);
  }


  public void rename(final String dn, final String newRDN,
                     final boolean deleteOldRDN,
                     final LDAPConstraints constraints)
         throws LDAPException
  {
    rename(dn, newRDN, null, deleteOldRDN, constraints);
  }


  public void rename(final String dn, final String newRDN,
                     final String newParentDN, final boolean deleteOldRDN)
         throws LDAPException
  {
    rename(dn, newRDN, newParentDN, deleteOldRDN, null);
  }


  public void rename(final String dn, final String newRDN,
                     final String newParentDN, final boolean deleteOldRDN,
                     final LDAPConstraints constraints)
         throws LDAPException
  {
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(dn, newRDN, deleteOldRDN, newParentDN);
    update(modifyDNRequest, constraints);

    try
    {
      final LDAPResult result = conn.modifyDN(modifyDNRequest);
      setResponseControls(result);
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  public LDAPSearchResults search(final String baseDN, final int scope,
              final String filter, final String[] attributes,
              final boolean typesOnly)
         throws LDAPException
  {
    return search(baseDN, scope, filter, attributes, typesOnly, null);
  }


  public LDAPSearchResults search(final String baseDN, final int scope,
              final String filter, final String[] attributes,
              final boolean typesOnly, final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    final LDAPSearchResults results;
    final LDAPSearchConstraints c =
         (constraints == null) ? searchConstraints : constraints;
    results = new LDAPSearchResults(c.getTimeLimit());

    try
    {
      final SearchRequest searchRequest = new SearchRequest(results, baseDN,
           SearchScope.valueOf(scope), filter, attributes);

      searchRequest.setDerefPolicy(
           DereferencePolicy.valueOf(c.getDereference()));
      searchRequest.setSizeLimit(c.getMaxResults());
      searchRequest.setTimeLimitSeconds(c.getServerTimeLimit());
      searchRequest.setTypesOnly(typesOnly);

      update(searchRequest, constraints);

      conn.asyncSearch(searchRequest);
      return results;
    }
    catch (com.hwlcn.ldap.ldap.sdk.LDAPException le)
    {
      debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }


  private Control[] getControls(final LDAPConstraints c)
  {
    Control[] controls = null;
    if (c != null)
    {
      controls = LDAPControl.toControls(c.getServerControls());
    }
    else if (constraints != null)
    {
      controls = LDAPControl.toControls(constraints.getServerControls());
    }

    if (controls == null)
    {
      return new Control[0];
    }
    else
    {
      return controls;
    }
  }


  private void update(final UpdatableLDAPRequest request,
                      final LDAPConstraints constraints)
  {
    final LDAPConstraints c =
         (constraints == null) ? this.constraints : constraints;

    request.setControls(LDAPControl.toControls(c.getServerControls()));
    request.setResponseTimeoutMillis(c.getTimeLimit());
    request.setFollowReferrals(c.getReferrals());
  }

  private void setResponseControls(final LDAPResult ldapResult)
  {
    if (ldapResult.hasResponseControl())
    {
      responseControls =
           LDAPControl.toLDAPControls(ldapResult.getResponseControls());
    }
    else
    {
      responseControls = null;
    }
  }


  private void setResponseControls(
                    final com.hwlcn.ldap.ldap.sdk.LDAPException ldapException)
  {
    if (ldapException.hasResponseControl())
    {
      responseControls =
           LDAPControl.toLDAPControls(ldapException.getResponseControls());
    }
    else
    {
      responseControls = null;
    }
  }
}
