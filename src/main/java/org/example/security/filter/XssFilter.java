// 2. 全局XSS过滤器（进阶防御）
package org.example.security.filter;

import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

import javax.servlet .*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class XssFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        XssHttpServletRequestWrapper xssRequest = new XssHttpServletRequestWrapper((HttpServletRequest) request);
        chain.doFilter(xssRequest, response);
    }

    // 重写getParameter方法，自动过滤所有参数
    static class XssHttpServletRequestWrapper extends javax.servlet.http.HttpServletRequestWrapper {
        public XssHttpServletRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            String value = super.getParameter(name);
            if (value == null) {
                return null;
            }
            // 转义XSS字符
            return HtmlUtils.htmlEscape(value);
        }
    }
}