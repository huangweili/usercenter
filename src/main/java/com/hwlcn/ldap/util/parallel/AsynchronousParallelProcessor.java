
package com.hwlcn.ldap.util.parallel;



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AsynchronousParallelProcessor<I, O>
{


  private final BlockingQueue<I> pendingQueue;
  private final ParallelProcessor<I, O> parallelProcessor;

 private final ResultProcessor<I, O> resultProcessor;

 private final InvokerThread invokerThread;
 private final AtomicBoolean shutdown = new AtomicBoolean(false);

 private final AtomicReference<Throwable> invocationException =
       new AtomicReference<Throwable>();


  public AsynchronousParallelProcessor(
       final BlockingQueue<I> pendingQueue,
       final ParallelProcessor<I, O> parallelProcessor,
       final ResultProcessor<I, O> resultProcessor)
  {
    this.pendingQueue = pendingQueue;
    this.parallelProcessor = parallelProcessor;
    this.resultProcessor = resultProcessor;

    this.invokerThread = new InvokerThread();
    this.invokerThread.start();
  }



  public AsynchronousParallelProcessor(
       final BlockingQueue<I> pendingQueue,
       final ParallelProcessor<I, O> parallelProcessor,
       final BlockingQueue<Result<I, O>> outputQueue)
  {
    this(pendingQueue, parallelProcessor,
         new OutputEnqueuer<I, O>(outputQueue));
  }



  public synchronized void submit(final I input)
       throws InterruptedException
  {
    if (shutdown.get())
    {
      throw new IllegalStateException("cannot call submit() after shutdown()");
    }

    final Throwable resultProcessingError = invocationException.get();
    if (resultProcessingError != null)
    {
      shutdown();
      throw new RuntimeException(resultProcessingError);
    }

    pendingQueue.put(input);
  }



  public synchronized void shutdown()
       throws InterruptedException
  {
    if (shutdown.getAndSet(true))
    {
      return;
    }

    invokerThread.join();

    parallelProcessor.shutdown();
  }



  private static final class OutputEnqueuer<I, O>
       implements ResultProcessor<I, O>
  {
    private final BlockingQueue<Result<I, O>> outputQueue;



    private OutputEnqueuer(final BlockingQueue<Result<I, O>> outputQueue)
    {
      this.outputQueue = outputQueue;
    }


    public void processResult(final Result<I, O> ioResult)
         throws Exception
    {
      outputQueue.put(ioResult);
    }
  }


  private final class InvokerThread
       extends Thread
  {

    private InvokerThread()
    {
      super("Asynchronous Parallel Processor");
      setDaemon(true);
    }


    @Override()
    public void run()
    {
      while (!(shutdown.get() && pendingQueue.isEmpty()))
      {
        try
        {
          final I item = pendingQueue.poll(100, TimeUnit.MILLISECONDS);
          if (item != null)
          {
            final List<I> items = new ArrayList<I>(1 + pendingQueue.size());
            items.add(item);
            pendingQueue.drainTo(items);

            final List<Result<I, O>> results =
                 parallelProcessor.processAll(items);

            for (final Result<I, O> result : results)
            {
              resultProcessor.processResult(result);
            }
          }
        }
        catch (Throwable e)
        {
          Debug.debugException(e);
          invocationException.compareAndSet(null, e);
        }
      }
    }
  }
}
