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

  private String salt;    //

  private String name;

  private String email;

  private String status; //用户状态

  private List<Role> roles; //角色

}
