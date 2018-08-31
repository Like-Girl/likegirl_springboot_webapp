package cn.like.girl.blog;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.junit.Test;

import java.util.Arrays;

public class SimpleTest {

    @Test
    public void test01(){
        RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();

        System.out.println(randomNumberGenerator.nextBytes().toHex());
        System.out.println(randomNumberGenerator.nextBytes().toHex());
        System.out.println(randomNumberGenerator.nextBytes().toHex());

    }

    @Test
    public void test02(){
        System.out.println(Arrays.toString(Base64.decode("2AvVhdsgUs0FSA3SDFAdag==")));

    }
}
