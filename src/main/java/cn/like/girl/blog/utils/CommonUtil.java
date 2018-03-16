package cn.like.girl.blog.utils;


import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommonUtil {
    public static boolean isAjaxRequest(HttpServletRequest request) {
        String requestType = request.getHeader("X-Requested-With");
        if("XMLHttpRequest".equals(requestType)) {
            return true;
        }
        return false;
    }

    public static String obtainRequestUA(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return (userAgent == null) ? "" : userAgent;
    }

    public static String obtainRequestBrowser(HttpServletRequest request) {
        String userAgent = obtainRequestUA(request);
        return obtainRequestBrowser(userAgent);
    }

    public static String obtainRequestOS(HttpServletRequest request) {
        String userAgent = obtainRequestUA(request);
        return obtainRequestOS(userAgent);
    }


    public static String obtainRequestBrowser(String userAgent) {
        String browser = "";
        String user = userAgent.toLowerCase();

        if (user.contains("msie"))
        {
            String substring=userAgent.substring(userAgent.indexOf("MSIE")).split(";")[0];
            browser=substring.split(" ")[0].replace("MSIE", "IE")+" "+substring.split(" ")[1];
        } else if (user.contains("safari") && user.contains("version"))
        {
            browser=(userAgent.substring(userAgent.indexOf("Safari")).split(" ")[0]).split("/")[0]+" "+(userAgent.substring(userAgent.indexOf("Version")).split(" ")[0]).split("/")[1];
        } else if ( user.contains("opr") || user.contains("opera"))
        {
            if(user.contains("opera")) {
                browser = (userAgent.substring(userAgent.indexOf("Opera")).split(" ")[0]).split("/")[0] + " " + (userAgent.substring(userAgent.indexOf("Version")).split(" ")[0]).split("/")[1];
            } else if(user.contains("opr")) {
                browser = ((userAgent.substring(userAgent.indexOf("OPR")).split(" ")[0]).replace("/", "-")).replace("OPR", "Opera");
            }
        } else if (user.contains("chrome"))
        {
            browser=(userAgent.substring(userAgent.indexOf("Chrome")).split(" ")[0]).replace("/", " ");
        } else if ((user.indexOf("mozilla/7.0") > -1) || (user.indexOf("netscape6") != -1)  || (user.indexOf("mozilla/4.7") != -1) || (user.indexOf("mozilla/4.78") != -1) || (user.indexOf("mozilla/4.08") != -1) || (user.indexOf("mozilla/3") != -1) )
        {
            //browser=(userAgent.substring(userAgent.indexOf("MSIE")).split(" ")[0]).replace("/", "-");
            browser = "Netscape ?";

        } else if (user.contains("firefox"))
        {
            browser=(userAgent.substring(userAgent.indexOf("Firefox")).split(" ")[0]).replace("/", " ");
        } else if(user.contains("rv"))
        {
            browser="IE " + user.substring(user.indexOf("rv") + 3, user.indexOf(")"));
        } else
        {
            browser = "UnKnown, More-Info: "+userAgent;
        }

        return browser;
    }

    public static String obtainRequestOS(String userAgent) {
        String os;
        String v = "";

        if (userAgent.toLowerCase().indexOf("windows") >= 0 )
        {
            os = "Windows";
            v = obtainWinVersion(userAgent);
        } else if(userAgent.toLowerCase().indexOf("macintosh") >= 0)
        {
            os = "Mac";
            v = obtainMacintoshVersion(userAgent);
        } else if(userAgent.toLowerCase().indexOf("x11") >= 0)
        {
            os = "Unix";
        } else if(userAgent.toLowerCase().indexOf("android") >= 0)
        {
            os = "Android";
            v = obtainAndroidVersion(userAgent);
        } else if(userAgent.toLowerCase().indexOf("iphone") >= 0)
        {
            os = "IPhone";
            v =  obtainIphoneVersion(userAgent);
        } else if(userAgent.toLowerCase().indexOf("ipad; cpu os ") >= 0) {
            os = "IPad";
            v = obtainIpadVersion(userAgent);
        } else{
            os = "UnKnown, More-Info: "+userAgent;
        }

        return (os + " " + v);
    }

    public static String obtainWinVersion(String win) {
        win = win.toLowerCase();

        //desktop
        if((win.indexOf("windows nt 6.4") >= 0) || (win.indexOf("windows nt 10") >= 0)) {
            return "10";
        }
        if(win.indexOf("windows nt 6.3") >= 0) {
            return "8.1";
        }
        if(win.indexOf("windows nt 6.2") >= 0) {
            return "8";
        }
        if(win.indexOf("windows nt 6.1") >= 0) {
            return "7";
        }
        if(win.indexOf("windows nt 6") >= 0) {
            return "Vista";
        }if(win.indexOf("windows nt 5.0") >= 0) {
            return "2000";
        }if(win.indexOf("windows nt 5") >= 0) {
            return "XP";
        }
        if((win.indexOf("windows 98") >= 0) || (win.indexOf("win98") >= 0)) {
            return "98";
        }

        //mobile
        if(win.indexOf("windows phone 10") >= 0) {
            return "10 Mobile";
        }
        if(win.indexOf("windows phone 8.1") >= 0) {
            return "Phone 8.1";
        }
        if(win.indexOf("windows phone 8") >= 0) {
            return "Phone 8";
        }
        if(win.indexOf("windows phone os 7") >= 0) {
            return "Phone 7";
        }
        if(win.indexOf("windows ce") >= 0) {
            return "Mobile";
        }
        if(win.indexOf("windows phone os 7") >= 0) {
            return "Phone 7";
        }
        if(win.indexOf("windows phone os 7") >= 0) {
            return "Phone 7";
        }
        if(win.indexOf("windows phone os 7") >= 0) {
            return "Phone 7";
        }

        return "";
    }

    public static String obtainAndroidVersion(String android) {
        android = android.toLowerCase();

        if((android.indexOf("android 6") >= 0) || (android.indexOf("android-6") >= 0)) {
            return "6.x";
        }
        if((android.indexOf("android 5") >= 0) || (android.indexOf("android-5") >= 0)) {
            return "5.x";
        }
        if((android.indexOf("android 4") >= 0) || (android.indexOf("android-4") >= 0)) {
            return "4.x";
        }
        if((android.indexOf("android 3") >= 0) || (android.indexOf("android-3") >= 0)) {
            return "3.x";
        }
        if((android.indexOf("android 2") >= 0) || (android.indexOf("android-2") >= 0)) {
            return "2.x";
        }
        if((android.indexOf("android 1") >= 0) || (android.indexOf("android-1") >= 0)) {
            return "1.x";
        }
        if(android.indexOf("mobile") >= 0) {
            return "mobile";
        }

        return "";
    }

    public static String obtainMacintoshVersion(String macintosh) {
        macintosh = macintosh.toLowerCase();
        //Macintosh; Intel Mac OS X 10_8_5
        Pattern pattern = Pattern.compile("macintosh; intel mac os x [0-9_.]+");
        Matcher matcher = pattern.matcher(macintosh);
        String macintosh_str = "";
        if(matcher.find()) {
            macintosh_str = matcher.group();
        }
        macintosh_str =
                macintosh_str
                        .replace("macintosh; intel mac os x ", "")
                        .replace("_", ".");
        return macintosh_str;
    }

    public static String obtainIphoneVersion(String iphone) {
        iphone = iphone.toLowerCase();
        //iPhone; CPU iPhone OS 10_3_2 like Mac OS X
        Pattern pattern = Pattern.compile("iphone os [0-9_]+ like mac os x");
        Matcher matcher = pattern.matcher(iphone);
        String iphone_str = "";
        if(matcher.find()) {
            iphone_str = matcher.group();
        }
        iphone_str =
                iphone_str
                        .replace("iphone os ", "")
                        .replace(" like mac os x", "")
                        .replace("_", ".");
        return iphone_str;
    }

    public static String obtainIpadVersion(String ipad) {
        ipad = ipad.toLowerCase();
        //iPad; CPU OS 10_2_1 like Mac OS X
        Pattern pattern = Pattern.compile("ipad; cpu os [0-9_]+ like mac os x");
        Matcher matcher = pattern.matcher(ipad);
        String ipad_str = "";
        if(matcher.find()) {
            ipad_str = matcher.group();
        }
        ipad_str =
                ipad_str
                        .replace("ipad; cpu os ", "")
                        .replace(" like mac os x", "")
                        .replace("_", ".");
        return ipad_str;
    }

}
