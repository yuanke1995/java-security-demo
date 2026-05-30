package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 未授权/越权访问漏洞演示控制器
 *
 * 漏洞类型：
 * 1. 未授权访问（Unauthorized Access）：用户无需身份验证即可访问受保护资源
 * 2. 水平越权（Horizontal Privilege Escalation）：用户可以访问同级别其他用户的资源
 * 3. 垂直越权（Vertical Privilege Escalation）：普通用户可以访问管理员级别的资源
 */
@Controller
public class UnauthorizedAccessVulnerableController {

    // 模拟用户数据库
    private final Map<Integer, User> userDatabase = new ConcurrentHashMap<>();
    // 模拟订单数据库
    private final Map<Integer, Order> orderDatabase = new ConcurrentHashMap<>();
    // 当前登录用户ID（简化版，实际应使用Session或Token）
    private Integer currentUserId = null;

    public UnauthorizedAccessVulnerableController() {
        // 初始化测试数据
        initTestData();
    }

    private void initTestData() {
        // 创建用户数据
        userDatabase.put(1, new User(1, "张三", "zhangsan@example.com", "13800138001", "user"));
        userDatabase.put(2, new User(2, "李四", "lisi@example.com", "13800138002", "user"));
        userDatabase.put(3, new User(3, "王五", "wangwu@example.com", "13800138003", "user"));
        userDatabase.put(4, new User(4, "管理员", "admin@example.com", "13800138004", "admin"));

        // 创建订单数据
        orderDatabase.put(1001, new Order(1001, 1, "iPhone 15 Pro", 7999.00, "已支付"));
        orderDatabase.put(1002, new Order(1002, 1, "MacBook Pro", 12999.00, "待发货"));
        orderDatabase.put(1003, new Order(1003, 2, "iPad Air", 4999.00, "已完成"));
        orderDatabase.put(1004, new Order(1004, 2, "AirPods Pro", 1999.00, "已支付"));
        orderDatabase.put(1005, new Order(1005, 3, "Apple Watch", 3199.00, "待支付"));
    }

    @GetMapping("/unauthorized-demo")
    public String unauthorizedDemoPage(Model model) {
        model.addAttribute("currentUserId", currentUserId);
        model.addAttribute("currentUser", currentUserId != null ? userDatabase.get(currentUserId) : null);
        return "unauthorized-demo";
    }

    /**
     * 危险接口：未授权访问 - 无需登录即可查看所有用户信息
     *
     * 漏洞原理：
     * - 没有进行身份验证检查
     * - 任何用户都可以直接访问该接口获取敏感信息
     * - 泄露了所有用户的隐私数据（手机号、邮箱等）
     *
     * 攻击方式：
     * - 直接访问 /api/users/list 接口
     * - 获取所有用户的敏感信息
     *
     * 风险后果：
     * - 用户隐私数据泄露
     * - 违反数据保护法规（如GDPR、个人信息保护法）
     * - 可能导致精准诈骗
     */
    @GetMapping("/api/users/list")
    @ResponseBody
    public Map<String, Object> vulnerableGetAllUsers() {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("message", "获取用户列表成功（未授权访问漏洞）");
        result.put("data", userDatabase.values());
        return result;
    }

    /**
     * 危险接口：水平越权 - 用户可以查看其他用户的订单
     *
     * 漏洞原理：
     * - 只验证了用户是否登录，但没有验证订单是否属于当前用户
     * - 攻击者可以通过修改订单ID来访问其他用户的订单信息
     * - 缺少所有权验证机制
     *
     * 攻击方式：
     * - 登录为用户1（ID=1）
     * - 访问 /api/orders/1003（这是用户2的订单）
     * - 成功获取到其他用户的订单详情
     *
     * 风险后果：
     * - 用户订单信息泄露
     * - 商业机密泄露
     * - 用户信任度下降
     */
    @GetMapping("/api/orders/{orderId}")
    @ResponseBody
    public Map<String, Object> vulnerableGetOrder(@PathVariable Integer orderId) {
        Map<String, Object> result = new HashMap<>();
        Order order = orderDatabase.get(orderId);

        if (order == null) {
            result.put("success", false);
            result.put("message", "订单不存在");
            return result;
        }

        // 漏洞：没有验证订单是否属于当前用户
        result.put("success", true);
        result.put("message", "获取订单成功（存在水平越权漏洞）");
        result.put("data", order);
        result.put("warning", "注意：此接口未验证订单归属，任何人都可以查看任意订单！");

        return result;
    }

    /**
     * 危险接口：垂直越权 - 普通用户可以执行管理员操作
     *
     * 漏洞原理：
     * - 没有进行权限级别检查
     * - 普通用户可以执行只有管理员才能执行的操作
     * - 缺少角色验证机制
     *
     * 攻击方式：
     * - 普通用户访问 /api/admin/delete-user/2
     * - 成功删除其他用户账号
     *
     * 风险后果：
     * - 数据被恶意删除或篡改
     * - 系统管理功能被滥用
     * - 系统安全性完全失效
     */
    @PostMapping("/api/admin/delete-user/{userId}")
    @ResponseBody
    public Map<String, Object> vulnerableDeleteUser(@PathVariable Integer userId) {
        Map<String, Object> result = new HashMap<>();
        User user = userDatabase.get(userId);

        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }

        // 漏洞：没有验证当前用户是否有管理员权限
        userDatabase.remove(userId);
        result.put("success", true);
        result.put("message", "用户删除成功（存在垂直越权漏洞）");
        result.put("deletedUser", user);
        result.put("warning", "注意：此接口未验证管理员权限，任何人都可以删除用户！");

        return result;
    }

    /**
     * 安全接口：正确实现的用户信息查询
     *
     * 修复思路：
     * 1. 身份验证：确保用户已登录
     * 2. 权限验证：验证用户是否有权限访问该资源
     * 3. 所有权验证：确保用户只能访问自己的资源
     * 4. 最小权限原则：用户只能访问必要的信息
     */
    @GetMapping("/api/users/safe/profile")
    @ResponseBody
    public Map<String, Object> safeGetUserProfile() {
        Map<String, Object> result = new HashMap<>();

        // 验证用户是否登录
        if (currentUserId == null) {
            result.put("success", false);
            result.put("message", "请先登录");
            return result;
        }

        // 只返回当前用户的信息
        User user = userDatabase.get(currentUserId);
        result.put("success", true);
        result.put("message", "获取用户信息成功");
        result.put("data", user.toSafeMap());

        return result;
    }

    /**
     * 安全接口：正确实现的订单查询
     */
    @GetMapping("/api/orders/safe/{orderId}")
    @ResponseBody
    public Map<String, Object> safeGetOrder(@PathVariable Integer orderId) {
        Map<String, Object> result = new HashMap<>();

        // 验证用户是否登录
        if (currentUserId == null) {
            result.put("success", false);
            result.put("message", "请先登录");
            return result;
        }

        Order order = orderDatabase.get(orderId);
        if (order == null) {
            result.put("success", false);
            result.put("message", "订单不存在");
            return result;
        }

        // 验证订单是否属于当前用户
        if (!order.getUserId().equals(currentUserId)) {
            result.put("success", false);
            result.put("message", "无权访问该订单");
            return result;
        }

        result.put("success", true);
        result.put("message", "获取订单成功");
        result.put("data", order);

        return result;
    }

    /**
     * 模拟登录接口
     */
    @PostMapping("/api/login")
    @ResponseBody
    public Map<String, Object> login(@RequestParam Integer userId) {
        Map<String, Object> result = new HashMap<>();
        User user = userDatabase.get(userId);

        if (user == null) {
            result.put("success", false);
            result.put("message", "用户不存在");
            return result;
        }

        currentUserId = userId;
        result.put("success", true);
        result.put("message", "登录成功");
        result.put("userId", userId);
        result.put("username", user.getUsername());
        result.put("role", user.getRole());

        return result;
    }

    /**
     * 模拟登出接口
     */
    @PostMapping("/api/logout")
    @ResponseBody
    public Map<String, Object> logout() {
        Map<String, Object> result = new HashMap<>();
        currentUserId = null;
        result.put("success", true);
        result.put("message", "登出成功");
        return result;
    }

    // 内部类：用户
    static class User {
        private Integer id;
        private String username;
        private String email;
        private String phone;
        private String role;

        public User(Integer id, String username, String email, String phone, String role) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.phone = phone;
            this.role = role;
        }

        public Integer getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getPhone() { return phone; }
        public String getRole() { return role; }

        // 返回脱敏后的用户信息
        public Map<String, Object> toSafeMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("id", id);
            map.put("username", username);
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

    // 内部类：订单
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
