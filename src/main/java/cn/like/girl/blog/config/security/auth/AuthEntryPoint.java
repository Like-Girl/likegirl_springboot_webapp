package cn.like.girl.blog.config.security.auth;

import cn.like.girl.blog.utils.CommonUtil;
import com.alibaba.fastjson.JSON;
import com.houde.sc.man.domain.json.CommonResponseJson;
import com.houde.sc.man.domain.json.ResponseJson;
import com.houde.sc.man.util.CodeMsgConstant;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Created by 009 on 2017/7/7.
 * Custom Login Authentication EntryPoint
 */
public class AuthEntryPoint extends LoginUrlAuthenticationEntryPoint {
    /**
     * @param loginFormUrl URL where the login page can be found. Should either be
     *                     relative to the web-app context path (include a leading {@code /}) or an absolute
     *                     URL.
     */
    public AuthEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        //
        boolean isAjax = CommonUtil.isAjaxRequest(request);
        if (isAjax) {
            ResponseJson responseJson =
                    new CommonResponseJson()
                            .init(CodeMsgConstant.CODE_REQUEST_ACCESS_DENY, CodeMsgConstant.CODE_REQUEST_ACCESS_DENY_MSG);

            String contentType = "application/json";
            response.setContentType(contentType);
            //response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            PrintWriter out = response.getWriter();
            out.print(JSON.toJSONString(responseJson));
            out.flush();
            out.close();
        } else {
            super.commence(request, response, authException);
        }
    }
}
