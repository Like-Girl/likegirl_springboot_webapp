package cn.like.girl.blog.service;

import cn.like.girl.blog.entity.MstDict;
import java.util.List;

public interface MstDictService {
	/**
	 * 查询所有
	 * @param page      当前页
	 * @param pageSize  页数大小
	 * @return 		 List<MstDict>
	 */
	public List<MstDict> findByPage(int page, int pageSize);
	
	/**
	 * 保存
	 * @param mstDict cn.like.girl.blog.entity.MstDict
	 * @return
	 */
	public boolean save(MstDict mstDict);

}
