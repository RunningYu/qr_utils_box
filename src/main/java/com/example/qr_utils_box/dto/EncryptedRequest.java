package com.example.qr_utils_box.dto;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * 请求加密数据请求体
 * @author : 其然乐衣Letitbe
 * @date : 2025/9/29
 */
@Data
public class EncryptedRequest {

    /**
     * 加密后的密钥（如：AES密钥）
     */
    private String encryptedKey;

    /**
     * 使用密钥加密后的业务数据
     */
    private String encryptedData;

    /**
     * 时间戳
     */
    private Long timestamp;

    /**
     * 随机数
     */
    private String nonce;

    /**
     * 签名
     */
    private String sign;

    public Map<String, Object> getParams() {
        Map<String, Object> map = new HashMap<>();
        map.put("encryptedKey", this.encryptedKey);
        map.put("encryptedData", this.encryptedData);
        map.put("timestamp", this.timestamp);
        map.put("nonce", this.nonce);
        map.put("sign", this.sign);
        return map;
    }
}
