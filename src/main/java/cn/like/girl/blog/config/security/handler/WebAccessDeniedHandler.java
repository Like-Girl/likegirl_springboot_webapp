package cn.like.girl.blog.config.security.handler;

import cn.like.girl.blog.utils.CommonUtil;
import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * DeniedHandler
 */
public class WebAccessDeniedHandler implements AccessDeniedHandler {
    private static final Logger LOG = LoggerFactory.getLogger(WebAccessDeniedHandler.class);
    private String errorPage;
    private String loginPage;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        if (accessDeniedException instanceof MissingCsrfTokenException ||
                accessDeniedException instanceof InvalidCsrfTokenException) {
            LOG.warn("Could not verify the provided CSRF token because your session was not found.");
        }

        if (request != null && !response.isCommitted()) {
            boolean isAjax = CommonUtil.isAjaxRequest(request);//"XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
            if (isAjax) {
                Map<String,Object> responseJson = new HashMap<>();
                responseJson.put("cdoe","106");
                responseJson.put("msg","权限不足");

                String contentType = "application/json";
                response.setContentType(contentType);
                PrintWriter out = response.getWriter();
                out.print(JSON.toJSONString(responseJson));
                out.flush();
                out.close();
                return;
            } else if ((loginPage).equals(request.getRequestURI())) {
                response.sendRedirect("/");
            } else if (errorPage != null) {
                // Put exception into request scope (perhaps of use to a view)
                request.setAttribute(WebAttributes.ACCESS_DENIED_403,
                        accessDeniedException);

                // Set the 403 status code.
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);

                // forward to error page.
                RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
                dispatcher.forward(request, response);
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        accessDeniedException.getMessage());
            }
        }
    }

    public void setErrorPage(String errorPage) {
        if ((errorPage != null) && !errorPage.startsWith("/")) {
            throw new IllegalArgumentException("errorPage must begin with '/'");
        }

        this.errorPage = errorPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }
}
