package com.example.qr_utils_box.utils.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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

    /**
     * AES加密数据
     * @param data 待加密数据
     * @param aesKey AES密钥
     * @return 加密后数据
     */
    public static String encrypt(String data, String aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]);
            byte[] keyBytes = Base64.getDecoder().decode(aesKey);
            SecretKeySpec sKeySpec = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, iv);
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES解密数据
     * @param encryptedData 待解密数据
     * @param aesKey AES密钥
     * @return 解密后数据
     */
    public static String decrypt(String encryptedData, String aesKey) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]);
            byte[] keyBytes = Base64.getDecoder().decode(aesKey);
            SecretKeySpec sKeySpec = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv);
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
