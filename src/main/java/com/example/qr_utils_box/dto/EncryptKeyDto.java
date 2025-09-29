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
     * 客户端私钥（用于加密AES密钥）
     */
    private String clientPublicKey;

    /**
     * 客户端公钥（用于解密AES密钥）
     */
    private String clientPrivateKey;

    /**
     * 服务端私钥（用于验签）
     */
    private String serverPublicKey;

    /**
     * 服务端公钥（用于签名）
     */
    private String serverPrivateKey;


}
