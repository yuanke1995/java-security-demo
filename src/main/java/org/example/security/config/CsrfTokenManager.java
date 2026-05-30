package org.example.security.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 纯手动CSRF Token管理器（不依赖Spring Security）
 * 提供完整的CSRF防护功能
 */
public class CsrfTokenManager {

    private static final String CSRF_TOKEN_SESSION_KEY = "csrf_token";
    private static final String CSRF_TOKEN_COOKIE_NAME = "CSRF_TOKEN";
    private static final int TOKEN_LENGTH = 32;
    private static final SecureRandom secureRandom = new SecureRandom();

    // Token黑名单（用于失效处理）
    private static final Map<String, Long> tokenBlacklist = new ConcurrentHashMap<>();
    // Token使用时间记录（用于检测重放攻击）
    private static final Map<String, Long> tokenUsageTime = new ConcurrentHashMap<>();

    /**
     * 生成新的CSRF Token
     * 使用SecureRandom生成强随机数
     *
     * @param request HTTP请求
     * @return 生成的Token字符串
     */
    public static String generateToken(HttpServletRequest request) {
        // 生成随机字节数组
        byte[] randomBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(randomBytes);

        // 编码为Base64字符串
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        // 存储到Session中
        request.getSession().setAttribute(CSRF_TOKEN_SESSION_KEY, token);

        // 同时设置到Cookie中（可选，用于双重验证）
        setCsrfCookie(request, null, token);

        // 记录生成时间
        tokenUsageTime.put(token, System.currentTimeMillis());

        System.out.println("✅ 生成新的CSRF Token: " + token.substring(0, 8) + "...");

        return token;
    }

    /**
     * 验证CSRF Token
     *
     * @param request HTTP请求
     * @param submittedToken 提交的Token
     * @return 是否验证通过
     */
    public static boolean validateToken(HttpServletRequest request, String submittedToken) {
        if (submittedToken == null || submittedToken.isEmpty()) {
            System.err.println("❌ CSRF验证失败：Token为空");
            return false;
        }

        // 从Session中获取存储的Token
        String sessionToken = (String) request.getSession().getAttribute(CSRF_TOKEN_SESSION_KEY);

        if (sessionToken == null) {
            System.err.println("❌ CSRF验证失败：Session中没有Token");
            return false;
        }

        // 检查Token是否在黑名单中
        if (tokenBlacklist.containsKey(submittedToken)) {
            System.err.println("❌ CSRF验证失败：Token已被列入黑名单");
            return false;
        }

        // 比较Token（使用恒定时间比较防止时序攻击）
        boolean isValid = constantTimeEquals(sessionToken, submittedToken);

        if (!isValid) {
            System.err.println("❌ CSRF验证失败：Token不匹配");
            logAttackAttempt(request, "Token不匹配");
            return false;
        }

        // 检查Token是否过期（默认2小时）
        Long tokenTime = tokenUsageTime.get(submittedToken);
        if (tokenTime != null && (System.currentTimeMillis() - tokenTime) > 2 * 60 * 60 * 1000) {
            System.err.println("❌ CSRF验证失败：Token已过期");
            return false;
        }

        System.out.println("✅ CSRF验证成功");
        return true;
    }

    /**
     * 从请求中提取CSRF Token
     * 优先从请求头获取，其次从参数获取
     *
     * @param request HTTP请求
     * @return Token字符串
     */
    public static String extractToken(HttpServletRequest request) {
        // 方式1：从请求头获取（推荐用于AJAX请求）
        String token = request.getHeader("X-CSRF-Token");

        // 方式2：从表单参数获取
        if (token == null || token.isEmpty()) {
            token = request.getParameter("csrf_token");
        }

        // 方式3：从Cookie获取（用于双重验证）
        if (token == null || token.isEmpty()) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (CSRF_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }
        }

        return token;
    }

    /**
     * 使Token失效（用于登出或敏感操作后）
     *
     * @param request HTTP请求
     */
    public static void invalidateToken(HttpServletRequest request) {
        String sessionToken = (String) request.getSession().getAttribute(CSRF_TOKEN_SESSION_KEY);

        if (sessionToken != null) {
            // 加入黑名单
            tokenBlacklist.put(sessionToken, System.currentTimeMillis());

            // 从Session中移除
            request.getSession().removeAttribute(CSRF_TOKEN_SESSION_KEY);

            // 清除Cookie
            setCsrfCookie(request, null, null);

            // 清理使用记录
            tokenUsageTime.remove(sessionToken);

            System.out.println("🗑️ CSRF Token已失效");
        }
    }

    /**
     * 刷新Token（用于敏感操作后）
     *
     * @param request HTTP请求
     * @return 新的Token
     */
    public static String refreshToken(HttpServletRequest request) {
        // 使旧Token失效
        invalidateToken(request);

        // 生成新Token
        return generateToken(request);
    }

    /**
     * 验证Referer头
     *
     * @param request HTTP请求
     * @param allowedDomains 允许的域名列表
     * @return 是否验证通过
     */
    public static boolean validateReferer(HttpServletRequest request, String... allowedDomains) {
        String referer = request.getHeader("Referer");

        if (referer == null || referer.isEmpty()) {
            System.err.println("⚠️ Referer头为空");
            return false;
        }

        // 检查Referer是否在允许的域名列表中
        for (String domain : allowedDomains) {
            if (referer.startsWith(domain)) {
                return true;
            }
        }

        System.err.println("❌ Referer验证失败：" + referer);
        logAttackAttempt(request, "Referer验证失败: " + referer);
        return false;
    }

    /**
     * 验证Origin头（用于AJAX请求）
     *
     * @param request HTTP请求
     * @param allowedOrigins 允许的来源列表
     * @return 是否验证通过
     */
    public static boolean validateOrigin(HttpServletRequest request, String... allowedOrigins) {
        String origin = request.getHeader("Origin");

        if (origin == null || origin.isEmpty()) {
            // 某些旧浏览器可能没有Origin头
            return true;
        }

        for (String allowedOrigin : allowedOrigins) {
            if (origin.equals(allowedOrigin)) {
                return true;
            }
        }

        System.err.println("❌ Origin验证失败：" + origin);
        return false;
    }

    /**
     * 设置CSRF Cookie
     *
     * @param request HTTP请求
     * @param response HTTP响应
     * @param value Cookie值
     */
    public static void setCsrfCookie(HttpServletRequest request, HttpServletResponse response, String value) {
        if (response == null) {
            return;
        }

        Cookie cookie = new Cookie(CSRF_TOKEN_COOKIE_NAME, value);
        cookie.setPath("/");
        cookie.setHttpOnly(false); // JavaScript需要读取
        cookie.setSecure(request.isSecure()); // HTTPS时设置为true
        cookie.setMaxAge(value != null ? 7200 : 0); // 2小时或立即过期

        response.addCookie(cookie);
    }

    /**
     * 恒定时间字符串比较（防止时序攻击）
     *
     * @param a 字符串a
     * @param b 字符串b
     * @return 是否相等
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }

        return result == 0;
    }

    /**
     * 记录攻击尝试
     *
     * @param request HTTP请求
     * @param reason 原因
     */
    public static void logAttackAttempt(HttpServletRequest request, String reason) {
        System.err.println("\n=== ⚠️ CSRF攻击被阻止 ===");
        System.err.println("原因：" + reason);
        System.err.println("IP地址：" + getClientIp(request));
        System.err.println("User-Agent：" + request.getHeader("User-Agent"));
        System.err.println("Referer：" + request.getHeader("Referer"));
        System.err.println("时间：" + new java.util.Date());
        System.err.println("=========================\n");
    }

    /**
     * 获取客户端真实IP
     *
     * @param request HTTP请求
     * @return IP地址
     */
    private static String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    /**
     * 清理过期的黑名单和记录（定期调用）
     */
    public static void cleanup() {
        long now = System.currentTimeMillis();
        long expiryTime = 24 * 60 * 60 * 1000; // 24小时

        // 清理黑名单
        tokenBlacklist.entrySet().removeIf(entry -> (now - entry.getValue()) > expiryTime);

        // 清理使用记录
        tokenUsageTime.entrySet().removeIf(entry -> (now - entry.getValue()) > expiryTime);

        System.out.println("🧹 CSRF Token记录已清理");
    }
}
