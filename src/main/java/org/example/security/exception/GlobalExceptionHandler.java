package org.example.security.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * 全局异常处理器
 * 处理控制器层的业务异常
 * 
 * 注意：CSRF异常在过滤器层抛出，不会被@RestControllerAdvice捕获
 * CSRF异常需要通过SecurityConfig中的AccessDeniedHandler处理
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 处理其他业务异常
     * （作为示例保留，CSRF异常不经过这里）
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        System.err.println("\n=== ⚠️ 业务异常 ===");
        System.err.println("错误类型：" + ex.getClass().getSimpleName());
        System.err.println("错误信息：" + ex.getMessage());
        System.err.println("=========================\n");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("error", "服务器内部错误");
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("code", 500);
        errorResponse.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}