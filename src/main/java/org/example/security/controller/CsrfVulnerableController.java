// 3. CSRF（跨站请求伪造）漏洞演示
package org.example.security.controller;

import org.example.security.config.CsrfTokenManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * CSRF（跨站请求伪造）漏洞演示控制器
 * 使用纯手动实现的CSRF防护（不依赖Spring Security）
 */
@Controller
public class CsrfVulnerableController {
    
    private double balance = 10000.00;

    @GetMapping("/csrf-demo")
    public String csrfDemoPage(Model model, HttpServletRequest request, HttpServletResponse response) {
        model.addAttribute("balance", String.format("%.2f", balance));
        
        // 生成CSRF Token
        String csrfToken = CsrfTokenManager.generateToken(request);
        model.addAttribute("csrfToken", csrfToken);
        
        // 设置Cookie（可选）
        CsrfTokenManager.setCsrfCookie(request, response, csrfToken);
        
        return "csrf-demo";
    }

    /**
     * 危险接口：没有CSRF防护的转账操作
     * 
     * 漏洞原理：
     * - 接口没有验证CSRF令牌
     * - 攻击者可以通过诱导用户访问恶意网站，
     *   该网站会自动向目标网站发送请求，执行转账操作
     */
    @PostMapping("/transfer/vulnerable")
    @ResponseBody
    public String vulnerableTransfer(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ☠️ 危险接口被调用（无CSRF防护）===");
        System.out.println("警告：此接口没有CSRF防护！");
        System.out.println("IP: " + request.getRemoteAddr());
        System.out.println("Referer: " + request.getHeader("Referer"));
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("⚠️  执行转账：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            return "⚠️  转账成功（危险操作 - 无CSRF防护）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance);
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 安全接口：使用手动CSRF Token防护（方式1 - 表单参数）
     * 
     * 防护机制：
     * 1. 页面加载时生成唯一的CSRF Token
     * 2. Token存储在Session中
     * 3. 表单提交时必须包含Token
     * 4. 服务器验证Token的有效性
     */
    @PostMapping("/transfer/safe-form")
    @ResponseBody
    public String safeTransferWithForm(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            @RequestParam String csrf_token,
            HttpServletRequest request) {
        
        System.out.println("\n=== ✅ 安全接口被调用（表单Token验证）===");
        
        // 手动验证CSRF Token
        if (!CsrfTokenManager.validateToken(request, csrf_token)) {
            return "❌ CSRF验证失败：无效或缺失的Token！请求被拒绝。";
        }
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("✅ 执行安全转账：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            // 敏感操作后刷新Token
            String newToken = CsrfTokenManager.refreshToken(request);
            
            return "✅ 安全转账成功（表单Token验证）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance) +
                   " | 新Token: " + newToken.substring(0, 8) + "...";
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 安全接口：使用手动CSRF Token防护（方式2 - 请求头）
     * 适用于AJAX请求
     */
    @PostMapping("/transfer/safe-header")
    @ResponseBody
    public String safeTransferWithHeader(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            HttpServletRequest request) {
        
        System.out.println("\n=== ✅ 安全接口被调用（请求头Token验证）===");
        
        // 从请求头提取Token
        String csrfToken = CsrfTokenManager.extractToken(request);
        
        // 验证Token
        if (!CsrfTokenManager.validateToken(request, csrfToken)) {
            return "❌ CSRF验证失败：请求头中的Token无效！";
        }
        
        // 验证Referer（额外保护）
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String scheme = request.getScheme();
        String allowedDomain = scheme + "://" + serverName + ":" + serverPort;
        
        if (!CsrfTokenManager.validateReferer(request, allowedDomain)) {
            return "❌ CSRF验证失败：非法的请求来源！";
        }
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("✅ 执行安全转账（请求头验证）：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            return "✅ 安全转账成功（请求头Token验证）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance);
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 安全接口：双重验证（Token + Referer）
     */
    @PostMapping("/transfer/safe-double")
    @ResponseBody
    public String safeTransferWithDoubleValidation(
            @RequestParam String toAccount, 
            @RequestParam String amount,
            @RequestParam String csrf_token,
            HttpServletRequest request) {
        
        System.out.println("\n=== ✅ 安全接口被调用（双重验证）===");
        
        // 第一层：验证CSRF Token
        if (!CsrfTokenManager.validateToken(request, csrf_token)) {
            CsrfTokenManager.logAttackAttempt(request, "Token验证失败");
            return "❌ 安全验证失败：Token无效！";
        }
        
        // 第二层：验证Referer
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String scheme = request.getScheme();
        String allowedDomain = scheme + "://" + serverName + ":" + serverPort;
        
        if (!CsrfTokenManager.validateReferer(request, allowedDomain)) {
            CsrfTokenManager.logAttackAttempt(request, "Referer验证失败");
            return "❌ 安全验证失败：请求来源非法！";
        }
        
        try {
            double transferAmount = Double.parseDouble(amount);
            if (transferAmount > balance) {
                return "❌ 转账失败：余额不足！当前余额：¥" + String.format("%.2f", balance);
            }
            
            balance -= transferAmount;
            System.out.println("✅ 执行安全转账（双重验证）：" + amount + " 到账户：" + toAccount);
            System.out.println("💰 当前余额：" + String.format("%.2f", balance));
            
            // 刷新Token
            CsrfTokenManager.refreshToken(request);
            
            return "✅ 安全转账成功（Token + Referer双重验证）：" + amount + " 到账户：" + toAccount + 
                   " | 剩余余额：¥" + String.format("%.2f", balance);
        } catch (Exception e) {
            return "❌ 转账失败：参数错误！";
        }
    }

    /**
     * 获取新的CSRF Token（用于AJAX请求）
     */
    @GetMapping("/api/csrf-token")
    @ResponseBody
    public String getCsrfToken(HttpServletRequest request, HttpServletResponse response) {
        String token = CsrfTokenManager.generateToken(request);
        CsrfTokenManager.setCsrfCookie(request, response, token);
        return "{\"token\":\"" + token + "\"}";
    }

    /**
     * 使当前Token失效（用于登出）
     */
    @PostMapping("/logout")
    @ResponseBody
    public String logout(HttpServletRequest request) {
        CsrfTokenManager.invalidateToken(request);
        return "{\"message\":\"已安全登出\"}";
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
}