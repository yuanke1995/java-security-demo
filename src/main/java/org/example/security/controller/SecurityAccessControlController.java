package org.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Spring Security防护未授权/越权访问演示控制器
 *
 * 演示内容：
 * 1. 使用Spring Security进行身份认证
 * 2. 基于角色的访问控制（RBAC）
 * 3. 资源所有权验证
 * 4. 方法级权限控制
 */
@Controller
public class SecurityAccessControlController {

    private final Map<Integer, User> userDatabase = new ConcurrentHashMap<>();
    private final Map<Integer, Order> orderDatabase = new ConcurrentHashMap<>();

    public SecurityAccessControlController() {
        initTestData();
    }

    private void initTestData() {
        userDatabase.put(1, new User(1, "zhangsan", "张三", "zhangsan@example.com", "13800138001", "USER"));
        userDatabase.put(2, new User(2, "lisi", "李四", "lisi@example.com", "13800138002", "USER"));
        userDatabase.put(3, new User(3, "wangwu", "王五", "wangwu@example.com", "13800138003", "USER"));
        userDatabase.put(4, new User(4, "admin", "管理员", "admin@example.com", "13800138004", "ADMIN"));

        orderDatabase.put(1001, new Order(1001, 1, "iPhone 15 Pro", 7999.00, "已支付"));
        orderDatabase.put(1002, new Order(1002, 1, "MacBook Pro", 12999.00, "待发货"));
        orderDatabase.put(1003, new Order(1003, 2, "iPad Air", 4999.00, "已完成"));
        orderDatabase.put(1004, new Order(1004, 2, "AirPods Pro", 1999.00, "已支付"));
        orderDatabase.put(1005, new Order(1005, 3, "Apple Watch", 3199.00, "待支付"));
    }

    /**
     * 演示页面
     */
    @GetMapping("/security-access-demo")
    public String demoPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            String username = auth.getName();
            User currentUser = userDatabase.values().stream()
                    .filter(u -> u.getUsername().equals(username))
                    .findFirst()
                    .orElse(null);
            
            model.addAttribute("isLoggedIn", true);
            model.addAttribute("username", username);
            model.addAttribute("roles", auth.getAuthorities());
            model.addAttribute("currentUser", currentUser);
        } else {
            model.addAttribute("isLoggedIn", false);
        }
        
        return "security-access-demo";
    }

    /**
     * 模拟登录接口（用于演示）
     * 注意：生产环境应使用Spring Security的标准登录流程
     */
    @PostMapping("/api/security/login")
    @ResponseBody
    public Map<String, Object> login(@RequestParam String username, 
                                     @RequestParam(required = false) String password,
                                     HttpSession session) {
        Map<String, Object> result = new HashMap<>();
        
        User user = userDatabase.values().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);
        
        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }
        
        // 创建认证令牌
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
        
        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(
                user.getUsername(), 
                password, 
                authorities
            );
        
        // 设置到SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // 将认证信息保存到Session
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        
        result.put("success", true);
        result.put("message", "登录成功");
        result.put("username", user.getDisplayName());
        result.put("role", user.getRole());
        result.put("userId", user.getId());
        
        return result;
    }

    /**
     * 登出接口
     */
    @PostMapping("/api/security/logout")
    @ResponseBody
    public Map<String, Object> logout(HttpSession session) {
        Map<String, Object> result = new HashMap<>();
        
        SecurityContextHolder.clearContext();
        session.invalidate();
        
        result.put("success", true);
        result.put("message", "登出成功");
        
        return result;
    }

    /**
     * 【安全接口】获取所有用户列表 - 需要ADMIN角色
     */
    @GetMapping("/api/security/users/list")
    @ResponseBody
    public Map<String, Object> getAllUsers() {
        Map<String, Object> result = new HashMap<>();

        result.put("success", true);
        result.put("message", "获取用户列表成功（需要ADMIN权限）");

        List<Map<String, Object>> safeUserList = new ArrayList<>();
        for (User user : userDatabase.values()) {
            safeUserList.add(user.toSafeMap());
        }
        result.put("data", safeUserList);
        result.put("protectedBy", "Spring Security - hasRole('ADMIN')");

        return result;
    }

    /**
     * 【安全接口】获取当前用户个人资料 - 需要登录
     */
    @GetMapping("/api/security/users/profile")
    @ResponseBody
    public Map<String, Object> getUserProfile() {
        Map<String, Object> result = new HashMap<>();
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        User currentUser = userDatabase.values().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);
        
        if (currentUser == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }
        
        result.put("success", true);
        result.put("message", "获取个人资料成功");
        result.put("data", currentUser.toSafeMap());
        result.put("protectedBy", "Spring Security - authenticated()");
        
        return result;
    }

    /**
     * 【安全接口】获取指定订单 - 需要登录且只能查看自己的订单
     */
    @GetMapping("/api/security/orders/{orderId}")
    @ResponseBody
    public Map<String, Object> getOrder(@PathVariable Integer orderId) {
        Map<String, Object> result = new HashMap<>();

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        User currentUser = userDatabase.values().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);

        if (currentUser == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }

        Order order = orderDatabase.get(orderId);
        if (order == null) {
            result.put("success", false);
            result.put("message", "订单不存在");
            return result;
        }

        if (!order.getUserId().equals(currentUser.getId())) {
            result.put("success", false);
            result.put("message", "无权访问该订单（只能查看自己的订单）");
            result.put("protectedBy", "Ownership Validation");
            return result;
        }

        result.put("success", true);
        result.put("message", "获取订单成功");
        result.put("data", order);
        result.put("protectedBy", "Spring Security + Ownership Check");

        return result;
    }

    /**
     * 【安全接口】删除指定用户 - 需要ADMIN角色
     */
    @PostMapping("/api/security/admin/delete-user/{userId}")
    @ResponseBody
    public Map<String, Object> deleteUser(@PathVariable Integer userId) {
        Map<String, Object> result = new HashMap<>();

        User user = userDatabase.get(userId);
        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }

        userDatabase.remove(userId);
        result.put("success", true);
        result.put("message", "用户删除成功（需要ADMIN权限）");
        result.put("deletedUser", user.toSafeMap());
        result.put("protectedBy", "Spring Security - hasRole('ADMIN')");

        return result;
    }

    /**
     * 【安全接口】获取所有订单 - 需要ADMIN角色
     */
    @GetMapping("/api/security/admin/orders/all")
    @ResponseBody
    public Map<String, Object> getAllOrders() {
        Map<String, Object> result = new HashMap<>();

        result.put("success", true);
        result.put("message", "获取所有订单成功（需要ADMIN权限）");
        result.put("data", orderDatabase.values());
        result.put("totalOrders", orderDatabase.size());
        result.put("protectedBy", "Spring Security - hasRole('ADMIN')");

        return result;
    }

    static class User {
        private Integer id;
        private String username;
        private String displayName;
        private String email;
        private String phone;
        private String role;

        public User(Integer id, String username, String displayName, String email, String phone, String role) {
            this.id = id;
            this.username = username;
            this.displayName = displayName;
            this.email = email;
            this.phone = phone;
            this.role = role;
        }

        public Integer getId() { return id; }
        public String getUsername() { return username; }
        public String getDisplayName() { return displayName; }
        public String getEmail() { return email; }
        public String getPhone() { return phone; }
        public String getRole() { return role; }

        public Map<String, Object> toSafeMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("id", id);
            map.put("username", username);
            map.put("displayName", displayName);
            map.put("email", maskEmail(email));
            map.put("phone", maskPhone(phone));
            map.put("role", role);
            return map;
        }

        private String maskEmail(String email) {
            if (email == null) return null;
            String[] parts = email.split("@");
            if (parts[0].length() <= 3) {
                return parts[0].charAt(0) + "***@" + parts[1];
            }
            return parts[0].substring(0, 3) + "***@" + parts[1];
        }

        private String maskPhone(String phone) {
            if (phone == null || !phone.matches("^1\\d{10}$")) {
                return phone;
            }
            return phone.replaceAll("(\\d{3})\\d{4}(\\d{4})", "$1****$2");
        }
    }

    static class Order {
        private Integer orderId;
        private Integer userId;
        private String productName;
        private Double price;
        private String status;

        public Order(Integer orderId, Integer userId, String productName, Double price, String status) {
            this.orderId = orderId;
            this.userId = userId;
            this.productName = productName;
            this.price = price;
            this.status = status;
        }

        public Integer getOrderId() { return orderId; }
        public Integer getUserId() { return userId; }
        public String getProductName() { return productName; }
        public Double getPrice() { return price; }
        public String getStatus() { return status; }
    }
}
