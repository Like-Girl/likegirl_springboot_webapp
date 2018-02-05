package cn.like.girl.blog.mapper;

import cn.like.girl.blog.config.database.BaseMapper;
import cn.like.girl.blog.entity.Role;
import cn.like.girl.blog.entity.UserRole;
import cn.like.girl.blog.entity.query.RoleQuery;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * Created by HD on 2018/1/31.
 */
public interface RoleMapper extends BaseMapper<Role> {

    List<String> findRoles(@Param("where") RoleQuery query);
}
