package com.example.qr_utils_box.dto;

import lombok.Data;

/**
 * 客户端和服务端两套RSA公私钥，分别用于AES密钥加解密、签名
 * @author : 其然乐衣Letitbe
 * @date : 2025/9/30
 */

@Data
public class EncryptKeyDto {

    /**
     * 客户端私钥（对参数签名，得到sign）
     */
    private String clientPublicKey;

    /**
     * 客户端公钥（校验签名sign）
     */
    private String clientPrivateKey;

    /**
     * 服务端私钥（解密randomKey，得到AES密钥）
     */
    private String serverPublicKey;

    /**
     * 服务端公钥（用于加密AES密钥，得到 randomKey）
     */
    private String serverPrivateKey;

    /**
     * AES密钥（用于加解密业务参数）
     */
    private String aesKey;


}
