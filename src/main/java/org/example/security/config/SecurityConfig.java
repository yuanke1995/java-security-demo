package org.example.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.security.filter.CsrfFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Spring Security配置类
 * 为Spring Security CSRF演示提供配置
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {


    //演示框架级csrf防御
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                // 1. CSRF配置
//                .csrf()
//                // 使用Cookie存储CSRF Token（JavaScript可读取）
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                // 只对特定的危险接口忽略CSRF（用于演示漏洞）
//                .ignoringRequestMatchers(
//                    new AntPathRequestMatcher("/security/transfer/vulnerable")
//                )
//                .and()
//
//                // 2. 授权配置 - 所有请求都允许访问（不需要登录）
//                .authorizeHttpRequests()
//                .antMatchers("/**").permitAll()
//                .anyRequest().permitAll()
//                .and()
//
//                // 3. 禁用表单登录（演示用，不需要登录）
//                .formLogin().disable()
//
//                // 4. 禁用HTTP Basic认证
//                .httpBasic().disable()
//
//                // 5. 禁用登出功能
//                .logout().disable()
//
//                // 6. 配置CSRF异常处理（关键！）
//                .exceptionHandling()
//                .accessDeniedHandler(customAccessDeniedHandler());
//
//        return http.build();
//    }

    //框架级权限配置
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeHttpRequests()
//                    .antMatchers(
//                        "/",
//                        "/unauthorized-demo",
//                        "/security-access-demo",
//                        "/api/users/list",
//                        "/api/orders/**",
//                        "/api/admin/**",
//                        "/api/login",
//                        "/api/logout",
//                        "/api/security/login",
//                        "/api/security/logout"
//                    ).permitAll()
//
//                    .antMatchers("/api/security/users/profile").authenticated()
//                    .antMatchers("/api/security/orders/**").authenticated()
//                    .antMatchers("/api/security/users/list").hasRole("ADMIN")
//                    .antMatchers("/api/security/admin/**").hasRole("ADMIN")
//                    .anyRequest().authenticated()
//                .and()
//                .httpBasic().disable()
//                .formLogin().disable()
//                .exceptionHandling()
//                .accessDeniedHandler(customAccessDeniedHandler());
//
//        return http.build();
//    }
    
    /**
     * 自定义CSRF验证失败的处理器
     * 返回JSON格式的错误信息而不是默认的403页面
     */
    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            // 记录日志
            System.err.println("\n=== ❌ CSRF验证失败 ===");
            System.err.println("错误类型：" + accessDeniedException.getClass().getSimpleName());
            System.err.println("错误信息：" + accessDeniedException.getMessage());
            System.err.println("请求路径：" + request.getRequestURI());
            System.err.println("请求方法：" + request.getMethod());
            System.err.println("IP地址：" + request.getRemoteAddr());
            System.err.println("=========================\n");
            
            // 设置响应状态码和内容类型
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            
            // 构建JSON响应
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", "CSRF验证失败");
            errorResponse.put("message", "无效的CSRF Token，请求被拒绝");
            errorResponse.put("code", 403);
            errorResponse.put("path", request.getRequestURI());
            errorResponse.put("timestamp", System.currentTimeMillis());
            
            // 写入响应
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                objectMapper.writeValue(response.getWriter(), errorResponse);
            } catch (IOException e) {
                System.err.println("写入响应失败：" + e.getMessage());
            }
        };
    }


    /**
     * 注册CSRF防护过滤器（自定义CSRF防护）
     * 对所有URL生效，但过滤器内部会排除GET请求和特定路径
     */
//    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilter() {
        FilterRegistrationBean<CsrfFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CsrfFilter());
        registration.addUrlPatterns("/*");
        registration.setName("csrfFilter");
        registration.setOrder(1);
        return registration;
    }

    /**
     * 不启用Security框架
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1. CSRF配置
                .csrf()
                .disable()


                // 2. 授权配置 - 所有请求都允许访问（不需要登录）
                .authorizeHttpRequests()
                .antMatchers("/**").permitAll()
                .anyRequest().permitAll()
                .and()

                // 3. 禁用表单登录（演示用，不需要登录）
                .formLogin().disable()

                // 4. 禁用HTTP Basic认证
                .httpBasic().disable()

                // 5. 禁用登出功能
                .logout().disable();

        return http.build();
    }
}