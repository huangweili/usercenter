
package com.hwlcn.ldap.util;


final class BackReferenceValuePatternComponent
      extends ValuePatternComponent
{

  private static final long serialVersionUID = 417294789313497595L;

  private final int index;

  BackReferenceValuePatternComponent(final int index)
  {
    this.index = index;
  }

  int getIndex()
  {
    return index;
  }



  @Override()
  void append(final StringBuilder buffer)
  {
    throw new AssertionError(
         "Unexpected call to BackReferenceValuePatternComponent.append");
  }

  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}
