package cn.like.girl.blog.service;

import cn.like.girl.blog.entity.User;

import java.util.Set;

/**
 * Created by HD on 2018/1/31.
 */
public interface UserService {

    User findByUserName(String userName);

}
