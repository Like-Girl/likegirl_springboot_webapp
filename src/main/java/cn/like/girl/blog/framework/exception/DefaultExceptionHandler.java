package cn.like.girl.blog.framework.exception;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
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
        mv.setViewName("views/unauthorized");
        return mv;
    }

    /**
     * 账号不存在 异常
     * <p/>
     * 后续根据不同的需求定制即可
     */
    @ExceptionHandler({UnknownAccountException.class})
    public ModelAndView processUnknownAccountException(NativeWebRequest request, UnknownAccountException e) {
        ModelAndView mv = new ModelAndView();
        mv.addObject("exception", e);
        mv.setViewName("login");
        return mv;
    }

    /**
     * 凭证不正确 异常
     * <p/>
     * 后续根据不同的需求定制即可
     */
    @ExceptionHandler({IncorrectCredentialsException.class})
    public ModelAndView processIncorrectCredentialsException(NativeWebRequest request, IncorrectCredentialsException e) {
        ModelAndView mv = new ModelAndView();
        mv.addObject("exception", e);
        mv.setViewName("login");
        return mv;
    }


    /**
     * 账号锁定 异常
     * <p/>
     * 后续根据不同的需求定制即可
     */
    @ExceptionHandler({LockedAccountException.class})
    //@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ModelAndView processLockedAccountException(NativeWebRequest request, LockedAccountException e) {
        ModelAndView mv = new ModelAndView();
        mv.addObject("exception", e);
        mv.setViewName("login");
        return mv;
    }


    @ExceptionHandler({AuthenticationException.class})
    //@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ModelAndView authenticationException(ModelAndView modelAndView,NativeWebRequest request, AuthenticationException e) {
        modelAndView.setViewName("login");
        return modelAndView;
    }

}
