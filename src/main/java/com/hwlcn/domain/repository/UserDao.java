package com.hwlcn.domain.repository;

import com.hwlcn.domain.entity.User;

/**
 * User: HuangWeili
 * Date: 13-7-20
 * Time: 下午5:21
 */

public interface UserDao {


    User getUserByAccountId(Long id);


}
