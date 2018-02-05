package cn.like.girl.blog.service;

import cn.like.girl.blog.mapper.*;

import javax.annotation.Resource;

/**
 * Created by HD on 2018/1/31.
 */
public class BaseService {

    @Resource
    protected UserMapper userMapper;

    @Resource
    protected RoleMapper roleMapper;

    @Resource
    protected UserRoleMapper userRoleMapper;

    @Resource
    protected PermissionMapper permissionMapper;

    @Resource
    protected RolePermissionMapper rolePermissionMapper;
}
