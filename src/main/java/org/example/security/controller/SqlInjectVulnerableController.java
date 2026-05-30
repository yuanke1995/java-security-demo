// 1. 危险代码（SQL注入）
package org.example.security.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SQL注入漏洞演示控制器
 * SQL注入是一种常见的Web安全漏洞，攻击者通过在用户输入中插入恶意SQL代码，
 * 使应用程序执行非预期的SQL语句，从而获取、修改或删除数据库中的数据。
 */
@Controller
public class SqlInjectVulnerableController {
    @Resource
    private JdbcTemplate jdbcTemplate;

    /**
     * SQL注入漏洞演示页面
     */
    @GetMapping("/sql-injection-demo")
    public String sqlInjectionDemoPage(Model model) {
        return "sql-injection-demo";
    }

    /**
     * 危险接口：直接拼接SQL参数，存在注入风险
     * 
     * 漏洞原理：
     * - 直接将用户输入拼接到SQL语句中，没有任何过滤或转义
     * - 攻击者可以通过输入特殊字符（如单引号）来改变SQL语句的结构
     * 
     * 攻击方式：
     * - 输入：1 or 1=1 → 生成SQL：select username from user where id = 1 or 1=1
     * - 这将导致查询所有用户数据，因为1=1始终为真
     * - 更严重的攻击：1; DROP TABLE user; --→ 可能删除整个用户表
     * 
     * 风险后果：
     * - 数据泄露：获取敏感用户信息
     * - 数据篡改：修改数据库中的数据
     * - 数据库损坏：删除表或数据
     * - 服务器被攻击：通过SQL注入执行系统命令
     */
    @PostMapping("/user/vulnerable")
    @ResponseBody
    public Map<String, Object> vulnerableGetUser(@RequestParam String id) {
        Map<String, Object> response = new HashMap<>();
        
        System.out.println("\n=== ☠️ 危险接口被调用（SQL注入漏洞）===");
        System.out.println("原始输入ID: " + id);
        
        try {
            // 危险做法：直接拼接用户输入到SQL语句中
            String sql = "select id, username from user where id = " + id; // 直接拼接！
            System.out.println("执行的SQL: " + sql);
            
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
            
            response.put("success", true);
            response.put("data", results);
            response.put("message", "查询成功（危险操作 - 未防护）");
            response.put("sqlExecuted", sql);
            
            System.out.println("查询结果数量: " + results.size());
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "查询失败: " + e.getMessage());
            response.put("error", e.getClass().getSimpleName());
            System.out.println("❌ 查询失败: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * 安全接口：预编译+参数校验
     * 
     * 修复思路：
     * 1. 参数校验：对用户输入进行严格的格式验证，只允许预期的输入格式
     * 2. 预编译SQL：使用参数化查询，将用户输入作为参数传递，而不是直接拼接到SQL语句中
     * 3. 最小权限原则：数据库用户只授予必要的权限，避免使用管理员权限
     * 4. 输入验证：对所有用户输入进行验证和过滤
     * 
     * 安全最佳实践：
     * - 使用ORM框架（如MyBatis、JPA）进行数据库操作
     * - 实施输入验证和参数绑定
     * - 定期进行安全审计和渗透测试
     * - 保持数据库和应用程序的安全补丁更新
     */
    @PostMapping("/user/safe")
    @ResponseBody
    public Map<String, Object> safeGetUser(@RequestParam String id) {
        Map<String, Object> response = new HashMap<>();
        
        System.out.println("\n=== ✅ 安全接口被调用（SQL注入防护）===");
        System.out.println("原始输入ID: " + id);
        
//        // 1. 参数校验：只允许数字
//        if (!id.matches("^\\d+$")) {
//            response.put("success", false);
//            response.put("message", "参数非法！ID必须是纯数字");
//            System.out.println("❌ 参数验证失败: ID包含非数字字符");
//            return response;
//        }
        
        try {
            // 2. 预编译SQL：使用?占位符，避免直接拼接
            String sql = "select id, username from user where id = ?";
            System.out.println("执行的SQL: " + sql);
            System.out.println("参数值: " + id);
            
            // 3. 参数绑定：将用户输入作为参数传递
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, new Object[]{id});
            
            response.put("success", true);
            response.put("data", results);
            response.put("message", "查询成功（安全操作 - 已防护）");
            response.put("sqlExecuted", sql);
            response.put("parameterUsed", id);
            
            System.out.println("✅ 查询结果数量: " + results.size());
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "查询失败: " + e.getMessage());
            response.put("error", e.getClass().getSimpleName());
            System.out.println("❌ 查询失败: " + e.getMessage());
        }
        
        return response;
    }
}