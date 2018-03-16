package cn.like.girl.blog.config.security.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * FailureHandler
 */
public class WebLoginFailureHandler implements AuthenticationFailureHandler {
    private static final Logger LOG = LoggerFactory.getLogger(WebLoginFailureHandler.class);
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException authException) throws IOException, ServletException {
        String errorPage = request.getRequestURI();
        //LOG.info("LOGIN_FAILURE_ERROR_INFO: {}", JSON.toJSONString(request.getUserPrincipal()));
        if(!response.isCommitted()) {
            if(errorPage != null) {
                request.setAttribute("errors", authException.getMessage());
                request.getRequestDispatcher("/login-error").forward(request, response);
            } else {
                //LOG.info("ERROR_PAGE_NULL: {}", authException.getMessage());
                request.setAttribute("errors", authException.getMessage());
                request.getRequestDispatcher("/login-error").forward(request, response);

                //response.sendError(404, authException.getMessage());
            }
        } else {
            //LOG.info("Response has committed");
        }

    }
}
