package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotExtensible;

import java.io.Serializable;


@NotExtensible()
abstract class ValuePatternComponent
         implements Serializable
{

  private static final long serialVersionUID = -5740038096026337244L;



  abstract void append(final StringBuilder buffer);


  abstract boolean supportsBackReference();
}
