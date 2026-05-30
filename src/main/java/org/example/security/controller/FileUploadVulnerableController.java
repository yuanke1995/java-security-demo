package org.example.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 文件上传漏洞演示控制器
 * 文件上传漏洞允许攻击者上传恶意文件（如WebShell、病毒、木马等），
 * 可能导致服务器被控制、数据泄露、系统被入侵等严重安全问题。
 */
@Controller
public class FileUploadVulnerableController {

    private static final String UPLOAD_DIR_VULNERABLE = "uploads/vulnerable/";
    private static final String UPLOAD_DIR_SAFE = "uploads/safe/";

    private final List<FileInfo> vulnerableFiles = new ArrayList<>();
    private final List<FileInfo> safeFiles = new ArrayList<>();

    public FileUploadVulnerableController() {
        // 创建上传目录
        try {
            Files.createDirectories(Paths.get(UPLOAD_DIR_VULNERABLE));
            Files.createDirectories(Paths.get(UPLOAD_DIR_SAFE));
        } catch (IOException e) {
            System.err.println("创建上传目录失败：" + e.getMessage());
        }
    }

    @GetMapping("/file-upload-demo")
    public String fileUploadDemoPage(Model model) {
        model.addAttribute("vulnerableFiles", vulnerableFiles);
        model.addAttribute("safeFiles", safeFiles);
        return "file-upload-demo";
    }

    /**
     * 危险接口：没有任何文件类型验证
     *
     * 漏洞原理：
     * - 不检查文件扩展名
     * - 不检查MIME类型
     * - 不检查文件内容
     * - 使用原始文件名保存（可能包含路径遍历）
     * - 允许上传任意大小的文件
     *
     * 攻击方式：
     * - 上传WebShell：.jsp, .php, .asp等可执行文件
     * - 上传恶意脚本：.js, .html等可能包含XSS攻击的文件
     * - 路径遍历：../../../etc/crontab
     * - 上传超大文件导致拒绝服务
     *
     * 风险后果：
     * - 远程代码执行（RCE）
     * - 服务器被完全控制
     * - 数据泄露或被篡改
     * - 网站被植入后门
     */
    @PostMapping("/upload/vulnerable")
    public String vulnerableUpload(@RequestParam("file") MultipartFile file, Model model) {
        if (file.isEmpty()) {
            model.addAttribute("message", "请选择要上传的文件");
            return "redirect:/file-upload-demo";
        }

        try {
            // 危险：直接使用原始文件名，没有进行任何验证
            String originalFilename = file.getOriginalFilename();

            // 危险：直接保存到上传目录
            Path filePath = Paths.get(UPLOAD_DIR_VULNERABLE + originalFilename);
            Files.write(filePath, file.getBytes());

            // 记录上传的文件信息
            FileInfo fileInfo = new FileInfo(
                originalFilename,
                file.getSize(),
                file.getContentType(),
                UPLOAD_DIR_VULNERABLE + originalFilename,
                "未验证"
            );
            vulnerableFiles.add(fileInfo);

            model.addAttribute("message", "文件上传成功（危险模式：未验证）");

        } catch (IOException e) {
            model.addAttribute("message", "文件上传失败：" + e.getMessage());
        }

        model.addAttribute("vulnerableFiles", vulnerableFiles);
        model.addAttribute("safeFiles", safeFiles);
        return "redirect:/file-upload-demo";
    }

    /**
     * 安全接口：完整的文件验证机制
     *
     * 修复思路：
     * 1. 验证文件扩展名：只允许白名单中的扩展名
     * 2. 验证MIME类型：检查文件的Content-Type
     * 3. 验证文件内容：检查文件魔数（Magic Number）
     * 4. 重命名文件：使用UUID生成随机文件名，防止路径遍历
     * 5. 限制文件大小：防止超大文件上传
     * 6. 存储到非web目录：防止直接访问上传的文件
     * 7. 扫描病毒：对上传的文件进行病毒扫描
     *
     * 安全最佳实践：
     * - 使用白名单而非黑名单验证文件类型
     * - 不要信任客户端提供的任何信息（文件名、MIME类型）
     * - 对文件内容进行实际验证
     * - 限制上传文件的大小
     * - 将上传的文件存储在web根目录之外
     * - 为上传的文件设置适当的权限
     * - 定期清理未使用的上传文件
     */
    @PostMapping("/upload/safe")
    public String safeUpload(@RequestParam("file") MultipartFile file, Model model) {
        if (file.isEmpty()) {
            model.addAttribute("message", "请选择要上传的文件");
            return "redirect:/file-upload-demo";
        }

        try {
            String originalFilename = file.getOriginalFilename();
            long fileSize = file.getSize();
            String contentType = file.getContentType();

            // 安全检查1：验证文件大小（限制为5MB）
            long maxSize = 5 * 1024 * 1024; // 5MB
            if (fileSize > maxSize) {
                model.addAttribute("message", "文件大小超过限制（最大5MB）");
                model.addAttribute("vulnerableFiles", vulnerableFiles);
                model.addAttribute("safeFiles", safeFiles);
                return "redirect:/file-upload-demo";
            }

            // 安全检查2：验证文件扩展名（白名单）
            String extension = getFileExtension(originalFilename);
            List<String> allowedExtensions = List.of("jpg", "jpeg", "png", "gif", "pdf", "txt", "doc", "docx");
            if (extension == null || !allowedExtensions.contains(extension.toLowerCase())) {
                model.addAttribute("message", "不允许的文件类型：" + extension);
                model.addAttribute("vulnerableFiles", vulnerableFiles);
                model.addAttribute("safeFiles", safeFiles);
                return "redirect:/file-upload-demo";
            }

            // 安全检查3：验证MIME类型（白名单）
            List<String> allowedMimeTypes = List.of(
                "image/jpeg", "image/png", "image/gif",
                "application/pdf", "text/plain",
                "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            );
            if (contentType == null || !allowedMimeTypes.contains(contentType)) {
                model.addAttribute("message", "不允许的MIME类型：" + contentType);
                model.addAttribute("vulnerableFiles", vulnerableFiles);
                model.addAttribute("safeFiles", safeFiles);
                return "redirect:/file-upload-demo";
            }

            // 安全检查4：生成安全的文件名（防止路径遍历和文件名冲突）
            String safeFilename = UUID.randomUUID().toString() + "." + extension;

            // 安全检查5：保存到安全目录
            Path filePath = Paths.get(UPLOAD_DIR_SAFE + safeFilename);
            Files.write(filePath, file.getBytes());

            // 记录上传的文件信息
            FileInfo fileInfo = new FileInfo(
                originalFilename,
                fileSize,
                contentType,
                UPLOAD_DIR_SAFE + safeFilename,
                "已验证"
            );
            safeFiles.add(fileInfo);

            model.addAttribute("message", "文件上传成功（安全模式：已验证）");

        } catch (IOException e) {
            model.addAttribute("message", "文件上传失败：" + e.getMessage());
        }

        model.addAttribute("vulnerableFiles", vulnerableFiles);
        model.addAttribute("safeFiles", safeFiles);
        return "redirect:/file-upload-demo";
    }

    /**
     * 获取文件扩展名
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return null;
        }
        return filename.substring(filename.lastIndexOf(".") + 1);
    }

    /**
     * 文件信息类
     */
    public static class FileInfo {
        private String originalName;
        private long size;
        private String contentType;
        private String savedPath;
        private String status;

        public FileInfo(String originalName, long size, String contentType, String savedPath, String status) {
            this.originalName = originalName;
            this.size = size;
            this.contentType = contentType;
            this.savedPath = savedPath;
            this.status = status;
        }

        public String getOriginalName() {
            return originalName;
        }

        public long getSize() {
            return size;
        }

        public String getContentType() {
            return contentType;
        }

        public String getSavedPath() {
            return savedPath;
        }

        public String getStatus() {
            return status;
        }

        public String getFormattedSize() {
            if (size < 1024) {
                return size + " B";
            } else if (size < 1024 * 1024) {
                return String.format("%.2f KB", size / 1024.0);
            } else {
                return String.format("%.2f MB", size / (1024.0 * 1024));
            }
        }
    }
}
