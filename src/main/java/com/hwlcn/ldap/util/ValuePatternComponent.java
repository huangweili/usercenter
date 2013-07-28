package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotExtensible;

import java.io.Serializable;



/**
 * This class defines an element that may be used to generate a portion of the
 * string representation of a {@link com.hwlcn.ldap.util.ValuePattern}.  All value pattern component
 * implementations must be completely threadsafe.
 */
@NotExtensible()
abstract class ValuePatternComponent
         implements Serializable
{

  private static final long serialVersionUID = -5740038096026337244L;



  abstract void append(final StringBuilder buffer);


  abstract boolean supportsBackReference();
}
