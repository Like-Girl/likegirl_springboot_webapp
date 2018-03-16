package cn.like.girl.blog.mapper;

import cn.like.girl.blog.config.database.BaseMapper;
import cn.like.girl.blog.entity.Permission;
import cn.like.girl.blog.entity.query.PermissionQuery;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * Created by HD on 2018/1/31.
 */
public interface PermissionMapper extends BaseMapper<Permission> {

    List<String> findPermissions(@Param("username") String username);
}
