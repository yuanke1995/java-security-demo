# Java安全漏洞演示项目

## 项目简介

本项目是一个用于安全培训的Java安全漏洞演示示例，包含了常见的Web安全漏洞及其修复方案。项目旨在帮助开发者和安全人员了解Java应用中的安全漏洞，学习如何识别和防御这些漏洞。

**核心特性**：
- ✅ 交互式漏洞演示页面（Vulnerable vs Safe 对比）
- ✅ Spring Security 防护机制演示
- ✅ 自动化安全测试用例
- ✅ 详细的安全最佳实践指南

## 项目结构

```
src/
├── main/java/org/example/security/ 
│ ├── config/ # 安全配置 
│ │ └── SecurityConfig.java # Spring Security配置 
│ ├── controller/ # 控制器 
│ │ ├── SqlInjectVulnerableController.java # SQL注入漏洞演示 
│ │ ├── XssVulnerableController.java # XSS漏洞演示 
│ │ ├── SensitiveInfoController.java # 敏感信息泄露演示 
│ │ ├── CsrfVulnerableController.java # CSRF漏洞演示 
│ │ ├── FileUploadVulnerableController.java # 文件上传漏洞演示 
│ │ ├── UnauthorizedAccessVulnerableController.java # 未授权/越权访问漏洞演示 
│ │ └── SecurityAccessControlController.java # Spring Security防护演示 
│ ├── filter/ # 过滤器 
│ │ ├── XssFilter.java # XSS过滤器 
│ │ └── CsrfFilter.java # CSRF过滤器 
│ ├── exception/ # 异常处理 
│ │ └── GlobalExceptionHandler.java # 全局异常处理器 
│ ├── util/ # 工具类 
│ │ └── SecurityUtils.java # 安全工具类 
│ └── SecurityApplication.java # 应用入口 
├── main/resources/ 
│ ├── templates/ # HTML演示页面 
│ │ ├── sql-injection-demo.html # SQL注入演示 
│ │ ├── xss-demo.html # XSS演示 
│ │ ├── sensitive-info-demo.html # 敏感信息泄露演示 
│ │ ├── csrf-demo.html # CSRF演示 
│ │ ├── file-upload-demo.html # 文件上传演示 
│ │ ├── unauthorized-demo.html # 未授权/越权演示 
│ │ └── security-access-demo.html # Spring Security防护演示 
│ └── application.yml # 应用配置 
└── test/java/org/example/security/ 
└── SecurityVulnerabilityTests.java # 安全漏洞测试
```

## 漏洞演示列表

### 1. SQL注入 (SQL Injection)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/user/vulnerable` | 使用字符串拼接，存在SQL注入风险 |
| ✅ 安全版 | `/user/safe` | 使用参数化查询，防止SQL注入 |

**演示页面**: `http://localhost:8080/sql-injection-demo`

**攻击示例**:
输入: ' OR '1'='1 
结果: 绕过身份验证，获取所有用户数据

**防护措施**:
- 使用预编译语句（PreparedStatement）
- 使用MyBatis的#{parameter}参数化查询
- 对用户输入进行严格验证

---

### 2. 跨站脚本攻击 (XSS)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/comment/vulnerable` | 直接输出用户输入，存在XSS风险 |
| ✅ 安全版 | `/comment/safe` | 对输出内容进行HTML转义 |

**演示页面**: `http://localhost:8080/xss-demo`

**攻击示例**:
输入: <script>alert('XSS')</script> 
结果: 在浏览器中执行恶意JavaScript代码

**防护措施**:
- 对输出到HTML的内容进行转义
- 使用XSS过滤器统一处理
- 实施内容安全策略（CSP）

---

### 3. 敏感信息泄露 (Sensitive Information Disclosure)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/user/info/vulnerable` | 返回完整的用户信息，包括密码、手机号等 |
| ✅ 安全版 | `/user/info/safe` | 对敏感信息进行脱敏处理 |

**演示页面**: `http://localhost:8080/sensitive-info-demo`

**泄露示例**:
json 
// 漏洞版本返回 { "password": "123456", "phone": "13800138000", "email": "user@example.com" }
// 安全版本返回 { "password": "***", "phone": "1388000", "email": "use@example.com" }

**防护措施**:
- 对敏感信息进行脱敏处理
- 使用强哈希算法加密存储密码
- 不在日志中记录完整的敏感信息

---

### 4. 跨站请求伪造 (CSRF)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/transfer/vulnerable` | 没有CSRF Token验证 |
| ✅ 安全版 | `/transfer/safe` | 使用Spring Security CSRF保护 |

**演示页面**: `http://localhost:8080/csrf-demo`

**攻击场景**:
1.用户登录银行网站
2.攻击者诱导用户点击恶意链接
3.恶意网站伪造转账请求
4.用户在不知情的情况下完成转账

**防护措施**:
- 使用CSRF Token验证
- 验证Referer头
- 使用Spring Security内置CSRF保护

---

### 5. 文件上传漏洞 (File Upload Vulnerability)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/upload/vulnerable` | 没有文件类型和大小限制 |
| ✅ 安全版 | `/upload/safe` | 严格的文件验证和安全存储 |

**演示页面**: `http://localhost:8080/file-upload-demo`

**攻击示例**:
上传: malware.php / shell.jsp 
结果: 在服务器执行恶意代码

**防护措施**:
- 验证文件扩展名和MIME类型
- 检查文件大小
- 重命名上传文件
- 存储在非Web目录

---

### 6. 未授权/越权访问 (Unauthorized Access)

| 类型 | 接口 | 说明 |
|------|------|------|
| ☠️ 漏洞版 | `/api/users/list`, `/api/orders/{id}`, `/api/admin/delete-user/{id}` | 没有身份验证和权限控制 |
| ✅ 安全版 | `/api/users/safe/profile`, `/api/orders/safe/{id}` | 需要登录且验证资源所有权 |

**演示页面**: `http://localhost:8080/unauthorized-demo`

**漏洞类型**:
- **未授权访问**: 无需登录即可访问受保护资源
- **水平越权**: 用户可以访问同级别其他用户的资源
- **垂直越权**: 普通用户可以执行管理员操作

**防护措施**:
- 强制身份验证
- 基于角色的访问控制（RBAC）
- 验证资源所有权
- 遵循最小权限原则

---

### 7. Spring Security防护演示 (Security Best Practices)

**演示页面**: `http://localhost:8080/security-access-demo`

**功能展示**:
- 🔐 用户认证与Session管理
- 🛡️ 基于角色的访问控制（RBAC）
- 📦 资源所有权验证
- 🗑️ 管理员权限控制

**接口列表**:

| 接口 | 权限要求 | 说明 |
|------|---------|------|
| `POST /api/security/login` | 公开 | 用户登录 |
| `POST /api/security/logout` | 公开 | 用户登出 |
| `GET /api/security/users/profile` | authenticated | 获取个人资料 |
| `GET /api/security/users/list` | ADMIN | 获取所有用户列表 |
| `GET /api/security/orders/{id}` | authenticated + 所有权 | 获取订单详情 |
| `POST /api/security/admin/delete-user/{id}` | ADMIN | 删除用户 |
| `GET /api/security/admin/orders/all` | ADMIN | 查看所有订单 |

**Spring Security核心特性**:
- ✅ 自动管理用户会话状态
- ✅ URL级别权限控制：`hasRole()`, `authenticated()`
- ✅ 方法级权限控制：`@PreAuthorize`注解
- ✅ 从SecurityContext获取真实用户信息
- ✅ 默认拒绝原则，显式授权访问

---

## 如何运行项目

### 环境要求

- JDK 1.8+
- Maven 3.6+

### 运行步骤

1. **克隆项目到本地**
bash git clone <repository-url> cd security
2. **启动项目**
bash mvn spring-boot:run
3. **访问演示页面**
   
   项目启动后，可通过以下地址访问各个演示页面：
   
   | 演示页面 | 访问地址 |
   |---------|---------|
   | SQL注入演示 | http://localhost:8080/sql-injection-demo |
   | XSS演示 | http://localhost:8080/xss-demo |
   | 敏感信息泄露演示 | http://localhost:8080/sensitive-info-demo |
   | CSRF演示 | http://localhost:8080/csrf-demo |
   | 文件上传演示 | http://localhost:8080/file-upload-demo |
   | 未授权/越权演示 | http://localhost:8080/unauthorized-demo |
   | Spring Security防护演示 | http://localhost:8080/security-access-demo |

---
扫描项目依赖库中的已知安全漏洞。

---

## 安全最佳实践

### 1. SQL注入防护
- ✅ 使用参数化查询或预编译语句
- ✅ 使用ORM框架（如MyBatis、JPA）
- ✅ 对用户输入进行严格验证
- ✅ 实施最小权限原则
- ❌ 避免字符串拼接SQL

### 2. XSS防护
- ✅ 对输出到HTML的内容进行转义
- ✅ 使用XSS过滤器统一处理
- ✅ 实施内容安全策略（CSP）
- ✅ 使用现代前端框架（内置XSS防护）
- ❌ 不要直接输出用户输入

### 3. 敏感信息保护
- ✅ 对敏感信息进行脱敏处理
- ✅ 使用BCrypt等强哈希算法加密密码
- ✅ 在日志中不记录完整的敏感信息
- ✅ 使用HTTPS加密传输
- ❌ 不要在响应中返回密码等敏感数据

### 4. CSRF防护
- ✅ 使用Spring Security内置CSRF保护
- ✅ 为每个表单生成唯一的CSRF Token
- ✅ 验证Referer头
- ✅ 实施适当的CORS策略
- ❌ 不要禁用CSRF保护

### 5. 文件上传安全
- ✅ 验证文件扩展名和MIME类型
- ✅ 检查文件大小
- ✅ 重命名上传文件（使用UUID）
- ✅ 存储在非Web可访问目录
- ❌ 不要信任客户端提供的文件名

### 6. 访问控制
- ✅ 强制身份验证（Spring Security）
- ✅ 基于角色的访问控制（RBAC）
- ✅ 验证资源所有权（防止水平越权）
- ✅ 区分用户和管理员权限（防止垂直越权）
- ✅ 从SecurityContext获取真实用户ID
- ❌ 不要信任客户端传入的用户标识

### 7. 通用安全措施
- ✅ 使用HTTPS加密传输数据
- ✅ 定期更新依赖库，修复已知漏洞
- ✅ 实施适当的访问控制
- ✅ 定期进行安全审计和渗透测试
- ✅ 记录安全相关的操作日志
- ✅ 设置合理的会话超时时间

---

## Spring Security配置说明

### 当前配置

项目使用Spring Security进行安全防护，主要配置在 `SecurityConfig.java` 中：
java 
@Bean 
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { 
http .csrf().disable() // 演示环境禁用CSRF 
.authorizeHttpRequests() // 公开接口 
.antMatchers("/api/security/login", "/api/security/logout")
.permitAll() // 需要认证的接口 
.antMatchers("/api/security/users/profile")
.authenticated() 
.antMatchers("/api/security/orders/")
.authenticated() // 需要ADMIN角色的接口 
.antMatchers("/api/security/users/list")
.hasRole("ADMIN") 
.antMatchers("/api/security/admin/")
.hasRole("ADMIN") 
.anyRequest().authenticated() .and() 
.exceptionHandling() 
.accessDeniedHandler(customAccessDeniedHandler());
return http.build();
}
### 权限级别

| 权限级别 | 说明 | 示例接口 |
|---------|------|---------|
| `permitAll()` | 所有人都可以访问 | 登录、演示页面 |
| `authenticated()` | 需要登录才能访问 | 查看个人资料、查看自己的订单 |
| `hasRole("ADMIN")` | 需要管理员角色 | 删除用户、查看所有订单 |

---

## 常见问题

### Q1: 为什么有些接口返回401 Unauthorized？
A: 这些接口需要先登录才能访问。请访问 `/security-access-demo` 页面，点击登录按钮进行登录。

### Q2: 为什么普通用户无法删除其他用户？
A: 删除用户接口需要ADMIN角色权限。这是Spring Security的垂直越权防护机制。

### Q3: 如何测试水平越权防护？
A: 
1. 登录为用户张三（ID=1）
2. 尝试查看订单1003（属于李四，ID=2）
3. 系统会返回"无权访问该订单"

### Q4: 生产环境应该如何配置？
A:
- 启用CSRF保护（`.csrf().enable()`）
- 使用HTTPS
- 配置合理的CORS策略
- 启用会话超时
- 添加速率限制
- 配置安全的HTTP头

---

## 参考资料

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Spring Security官方文档](https://spring.io/guides/gs/securing-web/)
- [Java安全编码标准](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

---

## 免责声明

本项目仅用于安全培训和教育目的，请勿将其用于任何恶意用途。使用本项目时，请确保遵守相关法律法规。

**警告**: 
- ⚠️ 漏洞演示接口仅用于学习，不应在生产环境中使用
- ⚠️ 所有演示数据均为虚构，不涉及真实用户信息
- ⚠️ 请在隔离的测试环境中运行本项目

---

## 更新日志

### v2.0 (2026-05-30)
- ✨ 新增Spring Security防护演示页面
- ✨ 新增未授权/越权访问漏洞演示
- ✨ 实现真实的Session认证机制
- 🛡️ 完善Spring Security配置
- 📝 更新README文档

### v1.0 (初始版本)
- SQL注入、XSS、CSRF、敏感信息泄露、命令注入漏洞演示
- 基础安全测试用例




   
