package cn.like.girl.blog.config.database;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.mybatis.spring.boot.autoconfigure.ConfigurationCustomizer;
import org.mybatis.spring.boot.autoconfigure.MybatisAutoConfiguration;
import org.mybatis.spring.boot.autoconfigure.MybatisProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration  
@ConditionalOnClass({EnableTransactionManagement.class})
@AutoConfigureAfter({DataSourceConfiguration.class})
@MapperScan(basePackages = "cn.like.girl.blog.mapper")
public class MybatisConfiguration extends MybatisAutoConfiguration {
	
	
private static final Logger LOGGER = LoggerFactory.getLogger(MybatisConfiguration.class);
	
	@Resource(name = "masterDataSource")
	private DataSource masterDataSource;
	
	@Resource(name = "slaveDataSource")
	private DataSource slaveDataSource;

	public MybatisConfiguration(MybatisProperties properties, ObjectProvider<Interceptor[]> interceptorsProvider, ResourceLoader resourceLoader, ObjectProvider<DatabaseIdProvider> databaseIdProvider, ObjectProvider<List<ConfigurationCustomizer>> configurationCustomizersProvider) {
		super(properties, interceptorsProvider, resourceLoader, databaseIdProvider, configurationCustomizersProvider);
	}


	@Bean(name = "sqlSessionFactory")
	@Override
	public SqlSessionFactory sqlSessionFactory(DataSource dataSource) throws Exception{
		LOGGER.info("------------create sqlSessionFactory------------");
		return super.sqlSessionFactory(roundRobinDataSourceProxy());
	}
	
	@Bean
	public AbstractRoutingDataSource roundRobinDataSourceProxy(){
		ReadWriteSplitRoutingDataSource proxy = new ReadWriteSplitRoutingDataSource();
		//主从数据源
		Map<Object,Object> targetDataSources = new HashMap<>();
		targetDataSources.put(DataBaseContextHolder.DataBaseType.MASTER, masterDataSource);
		targetDataSources.put(DataBaseContextHolder.DataBaseType.SLAVE, slaveDataSource);
		//默认数据源
		proxy.setDefaultTargetDataSource(masterDataSource);
		//代理数据源
		proxy.setTargetDataSources(targetDataSources);
		return proxy;
	}
}
