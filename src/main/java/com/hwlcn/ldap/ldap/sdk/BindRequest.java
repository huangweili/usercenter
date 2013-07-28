package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class BindRequest
       extends LDAPRequest
{

  protected static final ASN1Integer VERSION_ELEMENT = new ASN1Integer(3);

  private static final long serialVersionUID = -1509925217235385907L;

  protected BindRequest(final Control[] controls)
  {
    super(controls);
  }

  @Override()
  protected abstract BindResult process(final LDAPConnection connection,
                                        final int depth)
            throws LDAPException;

  @Override()
  public final OperationType getOperationType()
  {
    return OperationType.BIND;
  }

  public abstract String getBindType();

  public abstract BindRequest duplicate();

  public abstract BindRequest duplicate(final Control[] controls);

  public BindRequest getRebindRequest(final String host, final int port)
  {
    return null;
  }
}
