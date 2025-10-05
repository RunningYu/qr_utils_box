package com.example.qr_utils_box.utils.encrypt;

import com.example.qr_utils_box.dto.EncryptKeyDto;
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
    public static String encrypt(String data, EncryptKeyDto keyDto) {
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
        return "";
    }

    /**
     * 验签
     */
    public static boolean verify(String data, EncryptKeyDto keyDto, String sign) {
        return false;
    }

}
