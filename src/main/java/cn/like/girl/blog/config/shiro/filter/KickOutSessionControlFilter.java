package cn.like.girl.blog.config.shiro.filter;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

import com.alibaba.fastjson.JSON;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * @author LikeGirl
 */
public class KickOutSessionControlFilter extends AccessControlFilter {

    private static final String KICK_OUT = "kick_out";
    private static final Integer DEFAULT_MAX_SESSION = 1;
    private static final String DEFAULT_KICK_OUT_URL = "/";
    /**
     * 踢出前者
     */
    public static final Boolean KICK_OUT_AFTER = false;
    /**
     * 踢出后者
     */
    public static final Boolean KICK_OUT_BEFER = true;
    private static final String CACH_SESSION_PREFIX = "shiro_redis_cache";

    /**
     * 踢出后到的地址
     */
    private String kickOutUrl = DEFAULT_KICK_OUT_URL;
    /**
     * 踢出之前登录的/之后登录的用户
     * 默认踢出之前登录的用户
     */
    private boolean kickOutAfter = KICK_OUT_AFTER;
    /**
     * 同一个帐号最大会话数
     * 默认: DEFAULT_MAX_SESSION
     */
    private int maxSession = DEFAULT_MAX_SESSION;

    private SessionManager sessionManager;

    private Cache<String, Deque<Serializable>> cache;

    public void setKickOutUrl(String kickOutUrl) {
        this.kickOutUrl = kickOutUrl;
    }

    public void setKickOutAfter(boolean kickOutAfter) {
        this.kickOutAfter = kickOutAfter;
    }

    public void setMaxSession(int maxSession) {
        this.maxSession = maxSession;
    }

    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    /**
     * 设置Cache的key的前缀
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cache = cacheManager.getCache(CACH_SESSION_PREFIX);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        // 如果没有登录，直接进行之后的流程
        if (!subject.isAuthenticated() && !subject.isRemembered()) {
            return true;
        }

        Session session = subject.getSession();
        String username = (String) subject.getPrincipal();
        Serializable sessionId = session.getId();

        // 读取缓存   没有就存入
        Deque<Serializable> deque = cache.get(username);

        // 初始化队列
        if (deque == null) {
            deque = new LinkedList<>();
        }

        // 如果队列里没有此sessionId，且用户没有被踢出；放入队列
        if (!deque.contains(sessionId) && session.getAttribute(KICK_OUT) == null) {
            // 将sessionId存入队列
            deque.push(sessionId);
            // 将用户的sessionId队列缓存
            cache.put(username, deque);
        }

        // 如果队列里的sessionId数超出最大会话数，开始踢人
        while (deque.size() > maxSession) {
            Serializable kickOutSessionId;
            if (kickOutAfter) {
                kickOutSessionId = deque.removeFirst();
            } else {
                kickOutSessionId = deque.removeLast();
            }
            // 踢出后再更新下缓存队列
            cache.put(username, deque);
            try {
                // 获取被踢出的sessionId的session对象
                Session kickOutSession = sessionManager.getSession(new DefaultSessionKey(kickOutSessionId));
                if (kickOutSession != null) {
                    // 设置会话的KICK_OUT属性表示踢出了
                    kickOutSession.setAttribute(KICK_OUT, true);
                }
            } catch (Exception e) {
                // ignore exception
            }
        }

        // 若设置KICK_OUT属性：true
        // 说明被踢出
        // 重定向到踢出后的地址
        if (session.getAttribute(KICK_OUT) != null && (Boolean) session.getAttribute(KICK_OUT) == true) {
            try {
                subject.logout();
            } catch (Exception e) {
                // ignore exception
            }
            saveRequest(request);

            // 判断是不是Ajax请求
            if ("XMLHttpRequest".equalsIgnoreCase(((HttpServletRequest) request).getHeader("X-Requested-With"))) {
                Map<String, String> resultMap = new HashMap<>();
                resultMap.put("status", "300");
                resultMap.put("message", "您已经在其他地方登录，请重新登录！");
                // 输出json串
                out(response, resultMap);
            } else {
                // 重定向
                WebUtils.issueRedirect(request, response, kickOutUrl);
            }
            return false;
        }
        return true;
    }

    private void out(ServletResponse response, Map<String, String> resultMap) throws IOException {
        try {
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(JSON.toJSONString(resultMap));
            out.flush();
            out.close();
        } catch (Exception e) {
            System.err.println("KickOutSessionFilter.class 输出JSON异常,可以忽略。");
        }
    }
}
