package cn.like.girl.blog.service.impl;

import cn.like.girl.blog.config.database.ReadOnlyConnection;
import cn.like.girl.blog.entity.MstDict;
import cn.like.girl.blog.mapper.MstDictMapper;
import cn.like.girl.blog.service.MstDictService;
import com.github.pagehelper.PageHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional
public class MstDictServiceImpl implements MstDictService {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(MstDictServiceImpl.class);
	
	@Resource
	private MstDictMapper mstDictMapper;
	
	/**
	 * 查询所有
	 * @param page      当前页
	 * @param pageSize  页数大小
	 * @return 		 List<MstDict>
	 */

	@ReadOnlyConnection
	@Override
	public List<MstDict> findByPage(int page, int pageSize){
		LOGGER.info("---------------findByPage ReadOnlyConnection--------------");
		PageHelper.startPage(page, pageSize);
		List<MstDict> mstDicts = mstDictMapper.findByStatus("1");
		return mstDicts;
	}
	
	/**
	 * 保存
	 * @param mstDict cn.like.girl.blog.entity.MstDict
	 */
	@Override
	public boolean save(MstDict mstDict){
		int result = mstDictMapper.insert(mstDict);
		return result == 1;
	}

}
