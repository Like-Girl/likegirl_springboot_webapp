package cn.like.girl.blog.service;


import java.util.Set;

/**
 * Created by HD on 2018/2/1.
 */
public interface PermissionService {

    Set<String> findPermissions(String username);
}
