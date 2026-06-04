package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * Spring Security框架CSRF防护演示控制器
 * 展示如何使用Spring Security内置的CSRF保护机制
 */
@Controller
public class SecurityCsrfController {
    
    private double balance = 10000.00;

    /**
     * Spring Security CSRF演示页面
     */
    @GetMapping("/security-csrf-demo")
    public String securityCsrfDemoPage(Model model) {
        model.addAttribute("balance", String.format("%.2f", balance));
        return "security-csrf-demo";
    }

    /**
     * 危险接口：忽略CSRF验证（用于演示漏洞）
     * 在SecurityConfig中配置为ignoringRequestMatchers
     */
    @PostMapping("/security/transfer/vulnerable")
    @ResponseBody
    public String vulnerableTransfer(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ☠️ Spring Security - 危险接口（忽略CSRF）===");
        System.out.println("警告：此接口被配置为忽略CSRF验证！");
        System.out.println("IP: " + request.getRemoteAddr());
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("⚠️  执行转账：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            return "⚠️  转账成功（无CSRF防护）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance);
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 安全接口：Spring Security自动验证CSRF Token
     * 无需手动验证，框架自动处理
     */
    @PostMapping("/security/transfer/safe")
    @ResponseBody
    public String safeTransfer(
            @RequestParam String toAccount,
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ✅ Spring Security - 安全接口（自动CSRF验证）===");
        System.out.println("✅ Spring Security已自动验证CSRF Token");
        System.out.println("IP: " + request.getRemoteAddr());

        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("✅ 执行安全转账：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            return "✅ 转账成功（Spring Security CSRF防护）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance);
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 验证失败案例1：使用无效的CSRF Token
     * 这个接口故意不忽略CSRF，但前端会发送无效的Token
     * Spring Security会在到达这里之前就拦截并返回403
     */
    @PostMapping("/security/transfer/invalid-token")
    @ResponseBody
    public String transferWithInvalidToken(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ⚠️ Spring Security - 无效Token测试 ===");
        System.out.println("警告：不应该到达这里！如果到达说明CSRF配置有问题");
        
        return "⚠️ 意外成功：CSRF Token验证通过了（这不应该发生）";
    }

    /**
     * 验证失败案例2：完全没有CSRF Token的请求
     * 通过JavaScript模拟跨站请求
     * Spring Security会在到达这里之前就拦截并返回403
     */
    @PostMapping("/security/transfer/no-token")
    @ResponseBody
    public String transferWithoutToken(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ⚠️ Spring Security - 无Token测试 ===");
        System.out.println("警告：不应该到达这里！如果到达说明CSRF配置有问题");
        
        return "⚠️ 意外成功：没有CSRF Token也能访问（这不应该发生）";
    }

    /**
     * AJAX安全接口：同样享受Spring Security的CSRF保护
     */
    @PostMapping("/security/api/transfer")
    @ResponseBody
    public String apiTransfer(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ✅ Spring Security - API接口（CSRF验证）===");
        System.out.println("✅ CSRF Token验证通过（请求头方式）");
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "{\"success\":false,\"message\":\"余额不足\"}";
            }
            
            balance -= transferAmount;
            
            return "{\"success\":true,\"message\":\"转账成功\",\"balance\":\"" + 
                   String.format("%.2f", balance) + "\"}";
        } catch (Exception e) {
            return "{\"success\":false,\"message\":\"参数错误\"}";
        }
    }

    /**
     * 恶意网站演示页面
     * 这个页面模拟攻击者创建的钓鱼网站
     * 用于演示真实的 CSRF 攻击场景
     */
    @GetMapping("/malicious-site")
    public String maliciousSitePage() {
        return "malicious-site";
    }

    /**
     * 获取账户信息（GET请求，不需要CSRF Token）
     */
    @GetMapping("/security/api/balance")
    @ResponseBody
    public String getBalance() {
        return "{\"balance\":\"" + String.format("%.2f", balance) + "\"}";
    }

    @GetMapping("/updatePassword")
    public String updatePassword(Model model) {
        return "updatePassword";
    }
}
