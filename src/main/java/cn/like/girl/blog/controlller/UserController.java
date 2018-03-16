package cn.like.girl.blog.controlller;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Created by HD on 2017/8/1.
 */
@Controller
@RequestMapping("/user")
public class UserController {

    @RequestMapping(value = "/list",method = RequestMethod.GET)
    public String home(){
        return "views/list";
    }

    @RequiresRoles("admin")
    @RequestMapping(value = "/hello1",method = RequestMethod.GET)
    public String hello1() {
        //SecurityUtils.getSubject().checkRole("admin");
        return "views/success";
    }

    @RequiresRoles("user")
    @RequestMapping(value = "/commonality",method = RequestMethod.GET)
    @RequiresPermissions("user:commonality")
    public String commonality() {
        //SecurityUtils.getSubject().checkRole("admin");
        return "views/success";
    }

    @RequiresRoles("user")
    @RequestMapping("/hello2")
    public String hello2() {
        return "views/success";
    }
}
