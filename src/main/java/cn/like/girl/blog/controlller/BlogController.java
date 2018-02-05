package cn.like.girl.blog.controlller;

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
public class BlogController {

    @RequestMapping(value = "home",method = RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> home(Map<String,Object> map){
        Map<String,Object> resultMap = new HashMap<>();
        resultMap.put("code",0);
        resultMap.put("message","请求成功");
        resultMap.put("data",null);
        return resultMap;
    }

    @RequestMapping(value = "login",method = RequestMethod.GET)
    public String login(){
        return "login";
    }
}
