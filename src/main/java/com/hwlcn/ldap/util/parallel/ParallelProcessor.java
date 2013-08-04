
package com.hwlcn.ldap.util.parallel;



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.ldap.util.LDAPSDKThreadFactory;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;




@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ParallelProcessor<I, O>
{

  private final Processor<I, O> processor;


  private final List<Thread> workers;


  private final int minPerThread;


  private final Semaphore workerSemaphore = new Semaphore(0);


  private final AtomicReference<List<? extends I>> inputItems =
       new AtomicReference<List<? extends I>>();


  private final AtomicReference<List<Result<I, O>>> outputItems =
       new AtomicReference<List<Result<I, O>>>();


  private final AtomicInteger nextToProcess = new AtomicInteger();

  private volatile CountDownLatch processingCompleteSignal;


  private final AtomicBoolean shutdown = new AtomicBoolean();

  public ParallelProcessor(final Processor<I, O> processor,
                           final int totalThreads,
                           final int minPerThread)
  {
    this(processor, null, totalThreads, minPerThread);
  }



  public ParallelProcessor(final Processor<I, O> processor,
                           final ThreadFactory threadFactory,
                           final int totalThreads,
                           final int minPerThread)
  {
    Validator.ensureNotNull(processor);
    Validator.ensureTrue(totalThreads >= 1,
         "ParallelProcessor.totalThreads must be at least 1.");
    Validator.ensureTrue(totalThreads <= 1000,  // Upper bound on # of threads
         "ParallelProcessor.totalThreads must not be greater than 1000.");
    Validator.ensureTrue(minPerThread >= 1,
         "ParallelProcessor.minPerThread must be at least 1.");

    this.processor = processor;
    this.minPerThread = minPerThread;

    final ThreadFactory tf;
    if (threadFactory == null)
    {
      tf = new LDAPSDKThreadFactory("ParallelProcessor-Worker", true);
    }
    else
    {
      tf = threadFactory;
    }

    final int numExtraThreads = totalThreads - 1;
    final List<Thread> workerList = new ArrayList<Thread>(numExtraThreads);
    for (int i = 0; i < numExtraThreads; i++)
    {
      final Thread worker = tf.newThread(new Worker());
      workerList.add(worker);
      worker.start();
    }
    workers = workerList;
  }



  public synchronized ArrayList<Result<I, O>> processAll(
       final List<? extends I> items)
       throws InterruptedException, IllegalStateException
  {
    if (shutdown.get())
    {
      throw new IllegalStateException(
           "cannot call processAll() after shutdown()");
    }
    Validator.ensureNotNull(items);

    final int extraThreads =
         Math.min((items.size() / minPerThread) - 1, workers.size());

    if (extraThreads <= 0)
    {
      final ArrayList<Result<I, O>> output =
           new ArrayList<Result<I, O>>(items.size());
      for (final I item : items)
      {
        output.add(process(item));
      }
      return output;
    }

    processingCompleteSignal = new CountDownLatch(extraThreads);

    inputItems.set(items);

    final ArrayList<Result<I, O>> output =
         new ArrayList<Result<I, O>>(items.size());
    for (int i = 0; i < items.size(); i++)
    {
      output.add(null);
    }

    outputItems.set(output);
    nextToProcess.set(0);

    workerSemaphore.release(extraThreads);

    processInParallel();

    processingCompleteSignal.await();

    return output;
  }



  public synchronized void shutdown()
       throws InterruptedException
  {
    if (shutdown.getAndSet(true))
    {

      return;
    }

    workerSemaphore.release(workers.size());

    for (final Thread worker : workers)
    {
      worker.join();
    }
  }


  private void processInParallel()
  {
    try
    {
      final List<? extends I> items = inputItems.get();
      final List<Result<I, O>> outputs = outputItems.get();
      final int size = items.size();
      int next;
      while ((next = nextToProcess.getAndIncrement()) < size)
      {
        final I input = items.get(next);
        outputs.set(next, process(input));
      }
    }
    catch (Throwable e)
    {
      Debug.debugException(e);

    }
  }


  private ProcessResult process(final I input)
  {
    O output = null;
    Throwable failureCause = null;

    try
    {
      output = processor.process(input);
    }
    catch (Throwable e)
    {
      failureCause = e;
    }

    return new ProcessResult(input, output, failureCause);
  }



  private final class Worker
          implements Runnable
  {

    private Worker()
    {
    }



    public void run()
    {
      while (true)
      {
        try
        {

          workerSemaphore.acquire();
        }
        catch (InterruptedException e)
        {
          Debug.debugException(e);

        }

        if (shutdown.get())
        {
          return;
        }

        try
        {
          processInParallel();
        }
        finally
        {

          processingCompleteSignal.countDown();
        }
      }
    }
  }


  private final class ProcessResult
       implements Result<I, O>
  {
    private final I inputItem;


    private final O outputItem;

    private final Throwable failureCause;



    private ProcessResult(final I inputItem,
                          final O outputItem,
                          final Throwable failureCause)
    {
      this.inputItem = inputItem;
      this.outputItem = outputItem;
      this.failureCause = failureCause;
    }



    public I getInput()
    {
      return inputItem;
    }



    public O getOutput()
    {
      return outputItem;
    }


    public Throwable getFailureCause()
    {
      return failureCause;
    }
  }
}
