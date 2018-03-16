package cn.like.girl.blog.service.impl;


import cn.like.girl.blog.entity.query.PermissionQuery;
import cn.like.girl.blog.service.BaseService;
import cn.like.girl.blog.service.PermissionService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service(value = "permissionService")
@Transactional
public class PermissionServiceImpl extends BaseService implements PermissionService {


    @Override
    public Set<String> findPermissions(String username) {
        return new HashSet<>(permissionMapper.findPermissions(username));
    }
}