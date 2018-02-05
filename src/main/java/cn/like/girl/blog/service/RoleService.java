package cn.like.girl.blog.service;



import java.util.Set;

public interface RoleService {

    Set<String> findRoles(String username);
}
