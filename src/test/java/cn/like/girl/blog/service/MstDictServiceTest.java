package cn.like.girl.blog.service;

import org.apache.shiro.codec.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Optional;

/**
 * Created by HD on 2018/1/12.
 * @author HD
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class MstDictServiceTest {

    @Autowired
    private MstDictService mstDictService;

    @Test
    public void test2(){
        boolean result = Optional.ofNullable(mstDictService.findByPage(1, 5)).map(mstDicts->{
            mstDicts.forEach(mstDict->System.err.println(mstDict.getName()));
            return true;
        }).orElse(false);
        System.err.println(result);

    }

    @Autowired
    private RedisTemplate<String,String> redisTemplate;

    @Test
    public void test3(){
        ValueOperations<String, String> vo = redisTemplate.opsForValue();
        vo.set("sex", "女");
        System.err.println(vo.get("sex"));
    }

    @Test
    public void test4(){
        byte[] bytes = Base64.decode("2AvVhdsgUs0FSA3SDFAdag==");
        System.out.println("长度:"+bytes.length);
        for (byte b: bytes
             ) {
            System.out.println(b);
        }
    }
}
