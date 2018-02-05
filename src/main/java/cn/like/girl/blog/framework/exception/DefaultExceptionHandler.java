package cn.like.girl.blog.framework.exception;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class DefaultExceptionHandler {
    /**
     * 没有权限 异常
     * <p/>
     * 后续根据不同的需求定制即可
     */
    @ExceptionHandler({UnauthorizedException.class})
    //@ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ModelAndView processUnauthenticatedException(NativeWebRequest request, UnauthorizedException e) {
        ModelAndView mv = new ModelAndView();
        mv.addObject("exception", e);
        mv.setViewName("unauthorized");
        return mv;
    }


    @ExceptionHandler({LockedAccountException.class})
    //@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public Map<String,Object> lockedAccountException(NativeWebRequest request, LockedAccountException e) {
        Map<String,Object> resultMap = new HashMap<>();
        resultMap.put("result","error");
        resultMap.put("message",e.getMessage());
        return resultMap;
    }


    @ExceptionHandler({AuthenticationException.class})
    //@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ModelAndView authenticationException(ModelAndView modelAndView,NativeWebRequest request, AuthenticationException e) {
        modelAndView.setViewName("login");
        return modelAndView;
    }

}
