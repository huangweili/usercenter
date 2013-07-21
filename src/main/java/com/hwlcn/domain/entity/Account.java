package com.hwlcn.domain.entity;

import java.io.Serializable;
import java.util.List;

/**
 * User: HuangWeili
 * Date: 13-7-20
 * Time: 下午5:21
 */
public class Account implements Serializable{

  private Long id;          //用户ID

  private String loginName; //登录名称

  private String password; //密码

  private Long   invalPasswordDate; //密码失效日期

  private Long unlockTime; //

  private String theme; //风格

  private Long lastLoginTime; // 最后登录时间

  private Integer errCount; //错误登录次数

  private Long   startTime; //开始时间

  private Long   endTime;  //结束时间

  private String salt;    //

  private String name;    //显示名称

  private String email;   //邮箱地址

  private String status; //用户状态

  private List<Role> roles; //角色

}
