package cn.like.girl.blog;

import cn.like.girl.blog.config.shiro.credentials.RetryLimitHashedCredentialsMatcher;
import cn.like.girl.blog.entity.User;
import cn.like.girl.blog.utils.PasswordHelper;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ApplicationTests {

	@Autowired
	PasswordHelper passwordHelper;

	@Test
	public void contextLoads() {
		User user = new User();
		user.setUsername("li");
		user.setPassword("123");
		user.setSalt("612767570e8068b6fa974b575bf77e4a");
		// b045e8292bbdfe9db899a6b56b3bc461
		// a6dcd4d2b21df8074c9655b9abe82698
		passwordHelper.encryptPassword(user);
		System.out.println(user);
	}


}
