package cn.like.girl.blog.controlller;

import cn.like.girl.blog.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by HD on 2018/1/23.
 * @author HD
 */
@Controller
@RequestMapping("/")
public class IndexController {

    @RequestMapping(value = "home",method = RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> home(Map<String,Object> map){
        Map<String,Object> resultMap = new HashMap<>();
        resultMap.put("code",0);
        resultMap.put("message","请求成功");
        resultMap.put("data",null);
        return resultMap;
    }

    @RequestMapping(value = "",method = RequestMethod.GET)
    public String index(){
        return "redirect:user/list";
    }

    @RequestMapping(value = "login",method = RequestMethod.GET)
    public String login(){
        return "login";
    }

    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public String login(User user){
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(),user.getPassword());
        subject.login(token);
        return "redirect:user/list";
    }

    //踢出用户
    @RequestMapping(value="kickouting")
    @ResponseBody
    public String kickouting() {
        return "login";
    }

    //被踢出后跳转的页面
    @RequestMapping(value="kickout")
    public String kickout() {
        return "login";
    }

}
