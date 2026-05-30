package org.example.security.filter;


import org.example.security.config.CsrfTokenManager;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * CSRF防护拦截器（可选）
 * 对指定路径进行全局CSRF验证
 */
public class CsrfFilter implements Filter {

    private static final List<String> SAFE_METHODS = Arrays.asList("GET", "HEAD", "OPTIONS");
    private static final List<String> EXCLUDED_PATHS = Arrays.asList(
//        "/transfer/vulnerable",
        "/api/public/",
        "/static/",
        "/css/",
        "/js/",
        "/images/"
    );

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("✅ CSRF防护过滤器已初始化");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String method = httpRequest.getMethod();
        String path = httpRequest.getRequestURI();

        // GET、HEAD、OPTIONS请求不需要CSRF验证
        if (SAFE_METHODS.contains(method)) {
            chain.doFilter(request, response);
            return;
        }

        // 检查是否在排除列表中
        boolean excluded = EXCLUDED_PATHS.stream()
            .anyMatch(path::startsWith);

        if (excluded) {
            chain.doFilter(request, response);
            return;
        }

        // 提取并验证CSRF Token
        String csrfToken = CsrfTokenManager.extractToken(httpRequest);

        if (!CsrfTokenManager.validateToken(httpRequest, csrfToken)) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpResponse.setContentType("application/json;charset=UTF-8");
            httpResponse.getWriter().write("{\"error\":\"CSRF验证失败\",\"message\":\"无效的CSRF Token\"}");
            return;
        }

        // 验证通过，继续处理
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        System.out.println("🗑️ CSRF防护过滤器已销毁");
    }
}
