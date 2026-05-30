// 2. 敏感信息泄露漏洞演示
package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * 敏感信息泄露漏洞演示控制器
 * 敏感信息泄露是指应用程序在不适当的情况下暴露了敏感信息，
 * 如用户密码、身份证号、手机号等个人敏感数据，
 * 这可能导致用户隐私被侵犯、身份被冒用等安全问题。
 */
@Controller
public class SensitiveInfoController {
    
    // 模拟用户数据库
    private static final Map<String, UserInfo> userDatabase = new HashMap<>();
    
    static {
        // 初始化测试数据
        userDatabase.put("13800138000", new UserInfo("张三", "13800138000", "110101199001011234", "zhangsan@example.com", "123456"));
        userDatabase.put("13900139000", new UserInfo("李四", "13900139000", "110101199002022345", "lisi@example.com", "password123"));
        userDatabase.put("13700137000", new UserInfo("王五", "13700137000", "110101199003033456", "wangwu@example.com", "admin888"));
    }
    
    /**
     * 用户信息内部类
     */
    static class UserInfo {
        String name;
        String phone;
        String idCard;
        String email;
        String password;
        
        UserInfo(String name, String phone, String idCard, String email, String password) {
            this.name = name;
            this.phone = phone;
            this.idCard = idCard;
            this.email = email;
            this.password = password;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getIdCard() {
            return idCard;
        }

        public void setIdCard(String idCard) {
            this.idCard = idCard;
        }

        public String getPhone() {
            return phone;
        }

        public void setPhone(String phone) {
            this.phone = phone;
        }
    }
    
    /**
     * 敏感信息泄露演示页面
     */
    @GetMapping("/sensitive-info-demo")
    public String sensitiveInfoDemoPage(Model model) {
        model.addAttribute("users", userDatabase.values());
        return "sensitive-info-demo";
    }
    
    /**
     * 危险接口：返回完整敏感信息
     * 
     * 漏洞原理：
     * - 直接返回用户的敏感信息，如手机号和密码
     * - 在日志中打印完整的敏感信息
     * - 密码以明文形式存储和返回
     * 
     * 攻击方式：
     * - 通过接口直接获取用户的敏感信息
     * - 通过日志文件获取用户的敏感信息
     * - 利用网络嗅探获取传输中的敏感信息
     * 
     * 风险后果：
     * - 隐私泄露：用户的个人敏感信息被泄露
     * - 身份冒用：攻击者使用获取的信息冒充用户身份
     * - 财产损失：攻击者利用获取的信息进行诈骗或盗窃
     * - 法律风险：违反数据保护相关法律法规
     */
    @GetMapping("/user/info/vulnerable")
    @ResponseBody
    public Map<String, Object> vulnerableUserInfo(@RequestParam String phone) {
        System.out.println("\n=== ☠️ 危险接口 - 查询用户信息 ===");
        System.out.println("查询手机号：" + phone);
        
        Map<String, Object> result = new HashMap<>();
        UserInfo user = userDatabase.get(phone);
        
        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }
        
        // 危险做法：返回所有敏感信息（包括明文密码）
        result.put("success", true);
        result.put("data", new HashMap<String, Object>() {{
            put("name", user.name);
            put("phone", user.phone);
            put("idCard", user.idCard);
            put("email", user.email);
            put("password", user.password); // ⚠️ 明文密码！
        }});
        
        System.out.println("⚠️  返回了完整的用户信息（包含明文密码）");
        
        return result;
    }

    /**
     * 安全接口：脱敏返回+密码加密
     * 
     * 修复思路：
     * 1. 数据脱敏：对敏感信息进行脱敏处理，只返回部分信息
     * 2. 密码加密：使用安全的加密算法存储和处理密码
     * 3. 日志安全：在日志中不记录完整的敏感信息
     * 4. 传输加密：使用HTTPS等加密协议传输数据
     * 5. 访问控制：限制敏感信息的访问权限
     * 
     * 安全最佳实践：
     * - 对所有敏感信息进行脱敏处理
     * - 使用强哈希算法（如BCrypt）加密存储密码
     * - 实施最小权限原则，只授予必要的访问权限
     * - 使用HTTPS加密传输数据
     * - 定期进行安全审计和漏洞扫描
     */
    @GetMapping("/user/info/safe")
    @ResponseBody
    public Map<String, Object> safeUserInfo(@RequestParam String phone) {
        System.out.println("\n=== ✅ 安全接口 - 查询用户信息 ===");
        System.out.println("查询手机号：" + org.example.security.util.SecurityUtils.maskPhone(phone));
        
        Map<String, Object> result = new HashMap<>();
        UserInfo user = userDatabase.get(phone);
        
        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }
        
        // 安全做法：脱敏返回，不包含密码
        result.put("success", true);
        result.put("data", new HashMap<String, Object>() {{
            put("name", user.name);
            put("phone", org.example.security.util.SecurityUtils.maskPhone(user.phone));
            put("idCard", org.example.security.util.SecurityUtils.maskIdCard(user.idCard));
            put("email", org.example.security.util.SecurityUtils.maskEmail(user.email));
            put("password", "***"); // ✅ 不返回密码
            put("note", "敏感信息已脱敏，密码不返回");
        }});
        
        System.out.println("✅ 返回了脱敏后的用户信息");
        
        return result;
    }
}