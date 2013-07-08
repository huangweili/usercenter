package com.hwlcn.web.domain;

import java.io.Serializable;

/**
 * User: HuangWeili
 * Date: 13-6-22
 * Time: 下午9:21
 */
public class LdapTreeNode implements Serializable {

    private String id;       //节点ID

    private String icon;      //默认图标

    private String iconOpen;  //展开图标

    private String iconClose; //折叠图标

    private String name;  //节点名称

    private Boolean open; //是否展开

    private String iconSkin; //节点的css属性

    private String url; //超链接地址

    private String target; //打开目标

    private String click; //点击动作

    private String dn; //标识值

    private String type; //类型


}
