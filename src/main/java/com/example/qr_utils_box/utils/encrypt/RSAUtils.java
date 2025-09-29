package com.example.qr_utils_box.utils.encrypt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/9/28
 */
@Slf4j
@Component
public class RSAUtils {

    /**
     * 加密方法
     */
    public static String encrypt(String data, String publicKey) {
        return "";
    }

    /**
     * 解密方法
     */
    public static String decrypt(String data, String privateKey) {
        return "";
    }

    /**
     * 签名
     */
    public static String sign(String data, String privateKey) {
        return "";
    }

    /**
     * 验签
     */
    public static boolean verify(String data, String publicKey, String sign) {
        return false;
    }

}
