package com.example.qr_utils_box.utils.encrypt;

import com.example.qr_utils_box.dto.EncryptKeyDto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/10/12
 */
public class RasAesMixedUtils {
    /**
     * 加密方法
     */
    public static String encrypt(String data, EncryptKeyDto keyDto) {
        // 生成随机AES密钥
        // AES密钥对业务参数进行加密
        // RAS1公钥对AES密钥进行加密
        // RAS2私钥进行签名
        return "";
    }

    /**
     * 解密方法
     */
    public static String decrypt(String data, EncryptKeyDto keyDto) {
        return "";
    }

    /**
     * 签名
     */
    public static String sign(String data, EncryptKeyDto keyDto) {
        // 对加密的业务参数、加密的AES密钥、时间戳、盐值进行签名
        return "";
    }

    /**
     * 验签
     */
    public static boolean verify(String data, EncryptKeyDto keyDto, String sign) {
        return false;
    }


}
