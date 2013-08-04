package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.OutputStream;
import java.io.PrintStream;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NullOutputStream
       extends OutputStream
{

  private static final NullOutputStream INSTANCE = new NullOutputStream();



  private static final PrintStream PRINT_STREAM = new PrintStream(INSTANCE);




  public NullOutputStream()
  {
  }




  public static NullOutputStream getInstance()
  {
    return INSTANCE;
  }




  public static PrintStream getPrintStream()
  {
    return PRINT_STREAM;
  }



  @Override()
  public void close()
  {
  }



  @Override()
  public void flush()
  {
  }



  @Override()
  public void write(final byte[] b)
  {
  }




  @Override()
  public void write(final byte[] b, final int off, final int len)
  {

  }



  @Override()
  public void write(final int b)
  {

  }
}
