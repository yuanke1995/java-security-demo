package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 不安全的反序列化漏洞演示控制器
 * 反序列化漏洞发生在应用程序将外部数据转换为对象时，
 * 如果没有进行适当的验证，攻击者可以构造恶意数据执行任意代码。
 */
@Controller
public class DeserializationVulnerableController {

    @GetMapping("/deserialization-demo")
    public String deserializationDemoPage(Model model) {
        return "deserialization-demo";
    }

    /**
     * 危险接口：直接反序列化用户输入的数据
     *
     * 漏洞原理：
     * - 直接使用ObjectInputStream反序列化Base64解码后的数据
     * - 没有对反序列化的类进行任何限制或验证
     * - 攻击者可以构造包含恶意对象的序列化数据
     *
     * 攻击方式：
     * - 构造包含Runtime.exec()调用的恶意对象
     * - 利用常见的Gadget链（如Commons Collections）执行任意命令
     * - 通过反射机制调用危险方法
     *
     * 风险后果：
     * - 远程代码执行（RCE）：完全控制服务器
     * - 数据泄露：访问敏感文件和数据库
     * - 权限提升：获取更高权限
     * - 系统破坏：删除文件或停止服务
     */
    @PostMapping("/deserialize/vulnerable")
    @ResponseBody
    public Map<String, Object> vulnerableDeserialize(@RequestParam String serializedData) {
        Map<String, Object> response = new HashMap<>();

        System.out.println("\n=== ☠️ 危险接口被调用（不安全反序列化）===");
        System.out.println("接收到的Base64数据长度: " + serializedData.length());

        try {
            byte[] data = Base64.getDecoder().decode(serializedData);

            // 危险做法：直接反序列化，没有任何安全检查
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);

            // 这里会反序列化任意对象，包括恶意对象！
            Object obj = ois.readObject();
            ois.close();

            response.put("success", true);
            response.put("message", "反序列化成功（危险操作 - 未防护）");
            response.put("objectType", obj.getClass().getName());
            response.put("objectToString", obj.toString());
            response.put("warning", "⚠️ 这个操作非常危险！攻击者可能执行任意代码");

            // 如果对象包含命令执行结果，添加到响应中
            if (obj instanceof CommandExecutor) {
                CommandExecutor executor = (CommandExecutor) obj;
                response.put("commandOutput", executor.getOutput());
                response.put("executedCommand", executor.getCommand());
            }

            System.out.println("✅ 反序列化成功，对象类型: " + obj.getClass().getName());
            System.out.println("对象内容: " + obj.toString());

        } catch (ClassNotFoundException e) {
            response.put("success", false);
            response.put("message", "类未找到: " + e.getMessage());
            System.out.println("❌ 类未找到: " + e.getMessage());
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "反序列化失败: " + e.getMessage());
            System.out.println("❌ 反序列化失败: " + e.getMessage());
        }

        return response;
    }

    /**
     * 安全接口：使用白名单验证的反序列化
     *
     * 修复思路：
     * 1. 白名单机制：只允许特定的、可信的类进行反序列化
     * 2. 数据完整性校验：使用HMAC或数字签名验证数据来源
     * 3. 最小化反序列化：尽量避免使用Java原生序列化，改用JSON等安全格式
     * 4. 输入验证：对序列化数据进行严格的格式和长度验证
     *
     * 安全最佳实践：
     * - 优先使用JSON（Jackson/Gson）替代Java原生序列化
     * - 如果必须使用原生序列化，实施严格的白名单机制
     * - 对序列化数据进行签名和加密
     * - 定期更新依赖库，修复已知的Gadget链漏洞
     * - 使用SecurityManager限制反序列化的权限
     */
    @PostMapping("/deserialize/safe")
    @ResponseBody
    public Map<String, Object> safeDeserialize(@RequestParam String serializedData) {
        Map<String, Object> response = new HashMap<>();

        System.out.println("\n=== ✅ 安全接口被调用（安全反序列化）===");
        System.out.println("接收到的Base64数据长度: " + serializedData.length());

        try {
            byte[] data = Base64.getDecoder().decode(serializedData);

            // 安全措施1：数据长度验证
            if (data.length > 10240) {
                response.put("success", false);
                response.put("message", "数据过大，可能存在攻击");
                System.out.println("❌ 数据过大: " + data.length + " bytes");
                return response;
            }

            // 安全措施2：使用白名单ObjectInputStream
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            WhiteListObjectInputStream wois = new WhiteListObjectInputStream(bais);

            Object obj = wois.readObject();
            wois.close();

            response.put("success", true);
            response.put("message", "反序列化成功（安全操作 - 已防护）");
            response.put("objectType", obj.getClass().getName());
            response.put("objectToString", obj.toString());
            response.put("security", "✅ 使用了白名单验证，只允许可信的类");

            System.out.println("✅ 安全反序列化成功，对象类型: " + obj.getClass().getName());
            System.out.println("对象内容: " + obj.toString());

        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("message", "非法类被阻止: " + e.getMessage());
            System.out.println("❌ 安全拦截: " + e.getMessage());
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "反序列化失败: " + e.getMessage());
            System.out.println("❌ 反序列化失败: " + e.getMessage());
        }

        return response;
    }

    /**
     * 生成示例序列化数据（用于演示）
     */
    @GetMapping("/deserialize/generate-sample")
    @ResponseBody
    public Map<String, Object> generateSample() {
        Map<String, Object> response = new HashMap<>();

        try {
            // 创建一个简单的User对象并序列化
            User user = new User("张三", 25, "zhangsan@example.com");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(user);
            oos.close();

            String base64Data = Base64.getEncoder().encodeToString(baos.toByteArray());

            response.put("success", true);
            response.put("base64Data", base64Data);
            response.put("description", "这是一个合法的User对象序列化数据");
            response.put("userDetails", user.toString());

            System.out.println("✅ 生成示例数据成功");

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "生成失败: " + e.getMessage());
        }

        return response;
    }

    /**
     * 生成恶意示例序列化数据（用于演示安全防护）
     * 这个接口生成一个不在白名单中的类，用于测试安全区域的防护能力
     */
    @GetMapping("/deserialize/generate-malicious-sample")
    @ResponseBody
    public Map<String, Object> generateMaliciousSample() {
        Map<String, Object> response = new HashMap<>();

        System.out.println("\n=== 🛡️ 生成恶意示例数据（用于安全测试）===");

        try {
            // 创建一个恶意的Payload对象（模拟攻击者的恶意类）
            MaliciousPayload payload = new MaliciousPayload("test-command", "attacker@example.com");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(payload);
            oos.close();

            String base64Data = Base64.getEncoder().encodeToString(baos.toByteArray());

            response.put("success", true);
            response.put("base64Data", base64Data);
            response.put("description", "这是一个不在白名单中的恶意类（用于测试防护机制）");
            response.put("payloadDetails", payload.toString());
            response.put("warning", "⚠️ 这个对象会被安全区域的白名单机制拦截");

            System.out.println("✅ 生成恶意示例数据成功，类名: " + payload.getClass().getName());

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "生成失败: " + e.getMessage());
        }

        return response;
    }

    /**
     * 生成命令执行的恶意示例数据
     * 这个演示展示了攻击者如何通过反序列化执行系统命令
     */
    @GetMapping("/deserialize/generate-command-execution-sample")
    @ResponseBody
    public Map<String, Object> generateCommandExecutionSample() {
        Map<String, Object> response = new HashMap<>();

        System.out.println("\n=== 🚨 生成命令执行恶意样本 ===");

        try {
            // 创建一个会在反序列化时执行命令的恶意对象
            // 使用安全的命令（仅显示系统信息），不会造成实际损害
            CommandExecutor maliciousObj = new CommandExecutor("echo [安全演示] 如果是真实攻击，这里可能执行了 rm -rf / 或其他危险命令");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(maliciousObj);
            oos.close();

            String base64Data = Base64.getEncoder().encodeToString(baos.toByteArray());

            response.put("success", true);
            response.put("base64Data", base64Data);
            response.put("description", "这是一个包含命令执行能力的恶意对象（模拟攻击场景）");
            response.put("command", maliciousObj.getCommand());
            response.put("warning", "⚠️ 此对象在反序列化时会执行系统命令！");

            System.out.println("✅ 生成命令执行样本成功");

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "生成失败: " + e.getMessage());
        }

        return response;
    }

    /**
     * 内部类：白名单ObjectInputStream
     * 只允许特定的类进行反序列化
     */
    private static class WhiteListObjectInputStream extends ObjectInputStream {
        private static final String[] ALLOWED_CLASSES = {
            "org.example.security.controller.DeserializationVulnerableController$User",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Double",
            "java.lang.Boolean",
            "[Ljava.lang.String;" // String数组
        };

        public WhiteListObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();

            // 检查是否在白名单中
            boolean allowed = false;
            for (String allowedClass : ALLOWED_CLASSES) {
                if (className.equals(allowedClass)) {
                    allowed = true;
                    break;
                }
            }

            if (!allowed) {
                throw new IllegalArgumentException("不允许反序列化的类: " + className);
            }

            return super.resolveClass(desc);
        }
    }

    /**
     * 内部类：恶意Payload对象（用于演示攻击场景）
     * 这个类不在白名单中，会被安全区域的反序列化机制拦截
     */
    public static class MaliciousPayload implements Serializable {
        private static final long serialVersionUID = 1L;

        private String command;
        private String targetEmail;
        private String attackType = "SIMULATED_ATTACK";

        public MaliciousPayload() {}

        public MaliciousPayload(String command, String targetEmail) {
            this.command = command;
            this.targetEmail = targetEmail;
        }

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public String getTargetEmail() {
            return targetEmail;
        }

        public void setTargetEmail(String targetEmail) {
            this.targetEmail = targetEmail;
        }

        public String getAttackType() {
            return attackType;
        }

        @Override
        public String toString() {
            return "MaliciousPayload{command='" + command + "', targetEmail='" + targetEmail + 
                   "', attackType='" + attackType + "'} [此对象应该被拦截]";
        }
    }

    /**
     * 内部类：命令执行器（模拟真实的反序列化漏洞攻击）
     * 这个类演示了攻击者如何利用反序列化漏洞执行任意系统命令
     * 
     * ⚠️ 注意：为了安全演示，我们只在readObject中记录日志，不真正执行危险命令
     */
    public static class CommandExecutor implements Serializable {
        private static final long serialVersionUID = 1L;

        private String command;
        private transient String output;
        private boolean executed = false;

        public CommandExecutor() {}

        public CommandExecutor(String command) {
            this.command = command;
        }

        /**
         * 这个方法在对象反序列化时自动调用
         * 在真实攻击中，这里会执行恶意命令
         */
        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            // 先执行默认的反序列化
            ois.defaultReadObject();

            // 模拟命令执行（为了安全，我们不真正执行危险命令）
            System.out.println("\n🔴🔴🔴 [危险操作] 检测到命令执行尝试！🔴🔴🔴");
            System.out.println("如果要执行的命令: " + this.command);
            
            // 在实际攻击中，这里会是：
            // Process process = Runtime.getRuntime().exec(this.command);
            // BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            // StringBuilder result = new StringBuilder();
            // String line;
            // while ((line = reader.readLine()) != null) {
            //     result.append(line).append("\n");
            // }
            // this.output = result.toString();
            
            // 为了演示安全，我们只记录而不执行
            this.output = "[安全模式] 命令未实际执行，但真实攻击会造成严重危害！\n" +
                         "模拟命令: " + this.command + "\n" +
                         "时间: " + new java.util.Date();
            this.executed = true;

            System.out.println("命令已标记为执行状态（安全模式下未真正执行）");
            System.out.println("🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴\n");
        }

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public String getOutput() {
            return output;
        }

        public boolean isExecuted() {
            return executed;
        }

        @Override
        public String toString() {
            return "CommandExecutor{command='" + command + "', executed=" + executed + 
                   ", output='" + (output != null ? output.substring(0, Math.min(50, output.length())) : "null") + "...'}";
        }
    }

    /**
     * 内部类：示例User对象
     */
    public static class User implements Serializable {
        private static final long serialVersionUID = 1L;

        private String name;
        private int age;
        private String email;

        public User() {}

        public User(String name, int age, String email) {
            this.name = name;
            this.age = age;
            this.email = email;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        @Override
        public String toString() {
            return "User{name='" + name + "', age=" + age + ", email='" + email + "'}";
        }
    }
}