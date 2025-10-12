package com.example.qr_utils_box.utils.encrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/9/28
 */
public class AESUtils {

    /**
     * AES加密配置
     * 使用CBC模式和PKCS7填充
     * 使用256位密钥
     */
    public static final String AES_ALGORITHM = "AES/CBC/PKCS7Padding";
    public static final int AES_KEY_SIZE = 128;

    /**
     * 生成AES随机密钥
     */
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
