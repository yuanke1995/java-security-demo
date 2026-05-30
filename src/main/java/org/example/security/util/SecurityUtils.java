// 1. 密码加密 + 脱敏工具类
package org.example.security.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * 安全工具类
 * 提供密码加密、敏感信息脱敏、输入验证等安全相关功能
 */
public class SecurityUtils {
    // 密码加密器（单例）
    private static final BCryptPasswordEncoder PWD_ENCODER = new BCryptPasswordEncoder();
    // 安全随机数生成器
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    // 邮箱正则表达式
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    /**
     * 密码加密（BCrypt加盐，每次加密结果不同）
     */
    public static String encryptPassword(String rawPassword) {
        return PWD_ENCODER.encode(rawPassword);
    }

    /**
     * 密码校验
     */
    public static boolean matchPassword(String rawPassword, String encodedPassword) {
        return PWD_ENCODER.matches(rawPassword, encodedPassword);
    }

    /**
     * 手机号脱敏：13800138000 → 138****8000
     */
    public static String maskPhone(String phone) {
        if (phone == null || !phone.matches("^1\\d{10}$")) {
            return phone;
        }
        return phone.replaceAll("(\\d{3})\\d{4}(\\d{4})", "$1****$2");
    }

    /**
     * 身份证脱敏：110101199001011234 → 110101********1234
     */
    public static String maskIdCard(String idCard) {
        if (idCard == null || idCard.length() != 18) {
            return idCard;
        }
        return idCard.replaceAll("(\\d{6})\\d{8}(\\d{4})", "$1********$2");
    }

    /**
     * 邮箱脱敏：example@domain.com → exa***@domain.com
     */
    public static String maskEmail(String email) {
        if (email == null || !EMAIL_PATTERN.matcher(email).matches()) {
            return email;
        }
        String[] parts = email.split("@");
        if (parts[0].length() <= 3) {
            return parts[0].charAt(0) + "***@" + parts[1];
        }
        return parts[0].substring(0, 3) + "***@" + parts[1];
    }

    /**
     * 地址脱敏：北京市朝阳区建国路88号 → 北京市朝阳区********
     */
    public static String maskAddress(String address) {
        if (address == null || address.length() <= 8) {
            return address;
        }
        return address.substring(0, 8) + "********";
    }

    /**
     * 验证邮箱格式
     */
    public static boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * 验证密码强度
     * 要求：至少8位，包含大小写字母、数字和特殊字符
     */
    public static boolean isStrongPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSpecial = true;
            }
        }

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    /**
     * 生成安全的随机字符串
     * @param length 字符串长度
     */
    public static String generateSecureRandomString(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, length);
    }

    /**
     * Base64编码
     */
    public static String base64Encode(String input) {
        if (input == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(input.getBytes());
    }

    /**
     * Base64解码
     */
    public static String base64Decode(String input) {
        if (input == null) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(input));
        } catch (Exception e) {
            return null;
        }
    }
}

