package cn.like.girl.blog.mapper;


import cn.like.girl.blog.config.database.BaseMapper;
import cn.like.girl.blog.entity.MstDict;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface MstDictMapper extends BaseMapper<MstDict> {

    List<MstDict> findByStatus(@Param("status") String status);
}
