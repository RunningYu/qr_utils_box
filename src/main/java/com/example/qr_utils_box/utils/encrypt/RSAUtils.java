package com.example.qr_utils_box.utils.encrypt;

import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Component;
import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/9/28
 */

@Slf4j
@Component
public class RSAUtils {

    /**
     * AES加密配置
     * 使用PKCS1填充
     * 使用2048位密钥长度，提供足够的安全强度
     */
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final int RSA_KEY_SIZE = 2048;

    /**
     * RAS公钥加密
     * @param data 待加密数据
     * @param publicKeyStr 公钥字符串
     * @return 加密后数据
     * @throws Exception
     */
    public static String encryptByPublicKey(String data, String publicKeyStr) throws Exception {
        if (Strings.isBlank(publicKeyStr)) {
            throw new Exception("公钥为空");
        } else if (Strings.isBlank(data)) {
            throw new Exception("待加密数据为空");
        }
        PublicKey key = null;
        try {
            key = getPublicKeyFromX509("RSA", publicKeyStr);
        } catch (Exception e) {
            throw new Exception("加密异常", e);
        }
        return encrypt(data, key);
    }

    /**
     * RAS公钥加密
     * @param data 代加密数据
     * @param publicKey RAS公钥
     * @return Base64编码后的密文
     */
    public static String encrypt(String data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA私钥解密
     * @param encryptedData 待解密数据
     * @param privateKeyStr 私钥字符串
     * @return 解密后数据
     * @throws Exception
     */
    public static String rsaDecryptByPrivate(String encryptedData, String privateKeyStr) throws Exception {
        if (Strings.isBlank(privateKeyStr)) {
            throw new Exception("解密密钥为空");
        }
        if (Strings.isBlank(encryptedData)) {
            throw new Exception("待解密数据为空");
        }
        PrivateKey key = null;
        try {
            key = getPrivateKeyFromPKCS8("RSA", privateKeyStr);
        } catch (Exception var5) {
            throw new Exception("解密异常", var5);
        }
        return decrypt(encryptedData, key);
    }

    /**
     * RSA私钥解密
     * @param encryptedData 待解密数据
     * @param privateKey 私钥
     * @return 解密后数据
     * @throws Exception
     */
    public static String decrypt(String encryptedData, PrivateKey privateKey) {
        try {
            byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedData.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(encryptedDataBytes);
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * RAS私钥 签名
     */
    public static String sign(String data, String privateKeyStr) throws Exception {
        try {
            PrivateKey privateKey = getPrivateKeyFromPKCS8("RSA", privateKeyStr);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new Exception("RSA签名异常", e);
        }
    }

    /**
     * RAS公钥 验名
     */
    public static boolean verify(String data, String sign, String publicKeyStr) throws Exception {
        try {
            PublicKey pubKey = getPublicKeyFromX509("RSA", publicKeyStr);
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(pubKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
        } catch (Exception e) {
            throw new Exception("RSA签名验证错误,响应签名:" + sign, e);
        }
    }

    public static PublicKey getPublicKeyFromX509(String algorithm, String encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        byte[] key = Base64.getDecoder().decode(encodedKey);
        return keyFactory.generatePublic(new X509EncodedKeySpec(key));
    }

    public static PrivateKey getPrivateKeyFromPKCS8(String algorithm, String encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        byte[] key = Base64.getDecoder().decode(encodedKey);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
    }

}
