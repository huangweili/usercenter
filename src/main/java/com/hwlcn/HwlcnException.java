
package com.hwlcn;

/**
 * 系统异常基础

 */
public class HwlcnException extends RuntimeException {

    public HwlcnException(){
        super();
    }

    public HwlcnException(String message){
        super(message);
    }

   public HwlcnException(Throwable throwable){
       super(throwable);
   }

   public HwlcnException(String message,Throwable throwable){
       super(message,throwable);
   }
}

