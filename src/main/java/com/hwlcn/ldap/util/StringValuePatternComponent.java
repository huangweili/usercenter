
package com.hwlcn.ldap.util;


final class StringValuePatternComponent
      extends ValuePatternComponent
{

  private static final long serialVersionUID = -5948022796724341802L;

  private final String valueString;



  StringValuePatternComponent(final String valueString)
  {
    this.valueString = valueString;
  }

  @Override()
  void append(final StringBuilder buffer)
  {
    buffer.append(valueString);
  }


  @Override()
  boolean supportsBackReference()
  {
    return false;
  }
}
