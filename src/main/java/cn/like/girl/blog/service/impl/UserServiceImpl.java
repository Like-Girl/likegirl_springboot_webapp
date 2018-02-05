package cn.like.girl.blog.service.impl;

import cn.like.girl.blog.entity.User;
import cn.like.girl.blog.service.BaseService;
import cn.like.girl.blog.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

/**
 * Created by HD on 2018/1/31.
 */

@Service(value = "userService")
@Transactional
public class UserServiceImpl extends BaseService implements UserService {

    @Override
    public User findByUserName(String userName) {
        User user = new User();
        user.setUsername(userName);
        return userMapper.selectOne(user);
    }
}
