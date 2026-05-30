# Java安全漏洞演示项目

## 项目简介

本项目是一个用于安全培训的Java安全漏洞演示示例，包含了常见的Web安全漏洞及其修复方案。项目旨在帮助开发者和安全人员了解Java应用中的安全漏洞，学习如何识别和防御这些漏洞。

## 项目结构

```
src/
├── main/java/org/example/security/
│   ├── config/           # 安全配置
│   │   └── SecurityConfig.java     # Spring Security配置
│   ├── controller/       # 控制器
│   │   ├── SqlInjectVulnerableController.java     # SQL注入漏洞演示
│   │   ├── XssVulnerableController.java           # XSS漏洞演示
│   │   ├── SensitiveInfoController.java           # 敏感信息泄露演示
│   │   ├── CsrfVulnerableController.java          # CSRF漏洞演示
│   │   └── CommandInjectionVulnerableController.java  # 命令注入漏洞演示
│   ├── filter/           # 过滤器
│   │   └── XssFilter.java    # XSS过滤器
│   ├── util/             # 工具类
│   │   └── SecurityUtils.java   # 安全工具类
│   └── SecurityApplication.java  # 应用入口
└── test/java/org/example/security/
    ├── SecurityApplicationTests.java     # 基础测试
    └── SecurityVulnerabilityTests.java   # 安全漏洞测试
```

## 漏洞演示列表

| 漏洞类型 | 危险接口 | 安全接口 | 描述 |
|---------|---------|---------|------|
| SQL注入 | /user/vulnerable | /user/safe | 展示SQL注入漏洞的利用和防御 |
| XSS | /comment/vulnerable | /comment/safe | 展示XSS漏洞的利用和防御 |
| 敏感信息泄露 | /user/info/vulnerable | /user/info/safe | 展示敏感信息泄露的风险和防御 |
| CSRF | /transfer/vulnerable | /transfer/safe | 展示CSRF攻击的原理和防御 |
| 命令注入 | /file/view/vulnerable | /file/view/safe | 展示命令注入漏洞的利用和防御 |

## 如何运行项目

### 环境要求

- JDK 1.8+
- Maven 3.6+

### 运行步骤

1. 克隆项目到本地
2. 进入项目目录
3. 执行以下命令启动项目：

```bash
mvn spring-boot:run
```

4. 项目启动后，可通过以下地址访问：
   - 应用地址：http://localhost:8080

## 如何使用测试用例

### 运行安全漏洞测试

```bash
mvn test -Dtest=SecurityVulnerabilityTests
```

测试用例会演示各种安全漏洞的利用方式和防御效果，测试结果会输出到控制台。

## 安全最佳实践

1. **SQL注入防护**
   - 使用参数化查询或预编译语句
   - 对用户输入进行严格验证
   - 实施最小权限原则

2. **XSS防护**
   - 对输出到HTML的内容进行转义
   - 实施内容安全策略（CSP）
   - 使用现代前端框架，它们通常内置了XSS防护

3. **敏感信息保护**
   - 对敏感信息进行脱敏处理
   - 使用强哈希算法加密存储密码
   - 在日志中不记录完整的敏感信息

4. **CSRF防护**
   - 使用CSRF令牌
   - 验证Referer头
   - 实施适当的CORS策略

5. **命令注入防护**
   - 避免直接执行系统命令
   - 使用Java API代替系统命令
   - 对用户输入进行严格验证

6. **其他安全措施**
   - 使用HTTPS加密传输数据
   - 定期更新依赖库，修复已知漏洞
   - 实施适当的访问控制
   - 定期进行安全审计和渗透测试

## 参考资料

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Spring Security官方文档](https://spring.io/guides/gs/securing-web/)
- [Java安全编码标准](https://www.oracle.com/java/technologies/javase/seccodeguide.html)

## 免责声明

本项目仅用于安全培训和教育目的，请勿将其用于任何恶意用途。使用本项目时，请确保遵守相关法律法规。
