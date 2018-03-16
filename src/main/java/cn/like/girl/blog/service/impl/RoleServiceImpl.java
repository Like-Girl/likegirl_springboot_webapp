package cn.like.girl.blog.service.impl;


import cn.like.girl.blog.entity.Role;
import cn.like.girl.blog.entity.User;
import cn.like.girl.blog.entity.UserRole;
import cn.like.girl.blog.service.BaseService;
import cn.like.girl.blog.service.RoleService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tk.mybatis.mapper.entity.Condition;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service(value = "roleService")
@Transactional
public class RoleServiceImpl extends BaseService implements RoleService {


    @Override
    public Set<String> findRoles(String username) {
        return new HashSet<>(roleMapper.findRoles(username));
    }
}
