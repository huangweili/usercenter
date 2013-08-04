
package com.hwlcn.ldap.util;


import com.hwlcn.core.annotation.ThreadSafety;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum HorizontalAlignment
{

  LEFT(),

  CENTER(),

  RIGHT();


  public void format(final StringBuilder buffer, final String text,
                     final int width)
  {
    final int length = text.length();
    if (length >= width)
    {
      buffer.append(text.substring(0, width));
      return;
    }

    final int spacesBefore;
    final int spacesAfter;
    switch (this)
    {
      case LEFT:
        spacesBefore = 0;
        spacesAfter  = width - length;
        break;
      case CENTER:
        final int totalSpaces = width - length;
        spacesBefore = totalSpaces / 2;
        spacesAfter  = totalSpaces - spacesBefore;
        break;
      case RIGHT:
      default:
        spacesBefore = width - length;
        spacesAfter  = 0;
        break;
    }

    for (int i=0; i < spacesBefore; i++)
    {
      buffer.append(' ');
    }

    buffer.append(text);

    for (int i=0; i < spacesAfter; i++)
    {
      buffer.append(' ');
    }
  }
}
