package cn.like.girl.blog.config.shiro.credentials;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericToStringSerializer;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 凭证重试限制
 * <p>
 * 30s内重试3次以上，账号将被锁定
 */
//@Component
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        String username = (String) token.getPrincipal();
        //retry count + 1

        AtomicInteger retryCount = (AtomicInteger) redisTemplate.opsForValue().get(username);
        if (retryCount == null) {
            retryCount = new AtomicInteger(0);
        }
        if (retryCount.incrementAndGet() > 3) {
            //if retry count > 3 throw
//            throw new ExcessiveAttemptsException();
            throw new LockedAccountException();
        }
        boolean matches = super.doCredentialsMatch(token, info);
        if (matches) {
            //clear retry count
            redisTemplate.delete(username);
        } else {
            redisTemplate.opsForValue().set(username, retryCount, 30L, TimeUnit.SECONDS);
//        redisTemplate.opsForValue().set(username,retryCount);
        }
        return matches;
    }
}
