package com.example.qr_utils_box.utils.encrypt;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.qr_utils_box.dto.EncryptedRequest;

import java.util.Map;
import java.util.UUID;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/10/12
 */
public class RsaAesMixedUtils {

    /**
     * 加密方法
     */
    public static String encrypt(String data, String clientPrivateKey, String serverPublicKey, String salt) throws Exception {
        EncryptedRequest request = new EncryptedRequest();
        // 生成随机AES密钥
        String aesKeyStr = "96695747908994725758890194799371";
        // AES密钥对业务参数进行加密
        String encryptData = AESUtils.encrypt(data, aesKeyStr);
        // 对方的公钥对AES密钥进行加密
        String encryptAesKey = RSAUtils.encryptByPublicKey(aesKeyStr, serverPublicKey);

        request.setTimestamp(System.currentTimeMillis());
        request.setEncryptedData(encryptData);
        request.setEncryptedKey(encryptAesKey);
        request.setNonce(String.valueOf(UUID.randomUUID()));

        // 自己的RAS私钥进行签名
        String sing = RSAUtils.sign(RSAUtils.sortParams(request.getParams(), salt), clientPrivateKey);
        request.setSign(sing);

        return JSON.toJSONString(request);
    }

    /**
     * 解密方法
     * @param data 接口响应参数
     * @param clientPublicKey 客户端公钥（自己的公钥）
     * @param serverPrivateKey 服务端私钥（对方的私钥）
     * @param salt 盐值
     * @return 解密后的业务数据
     */
    public static String decrypt(String data, String clientPublicKey, String serverPrivateKey, String salt) throws Exception {
        Map<String, Object> receivedParamMap = JSONObject.parseObject(data).getInnerMap();
        String sign = (String) receivedParamMap.get("sign");
        receivedParamMap.remove("sign");
        String sortParams = RSAUtils.sortParams(receivedParamMap, salt);
        // 验签
        boolean pass = RSAUtils.verifySign(sortParams, sign, clientPublicKey);
        if (!pass) {
            throw new Exception("RSA签名验证错误,响应签名:" + sign);
        }
        // 解密获取AES密钥
        String aesKey = RSAUtils.rsaDecryptByPrivate(receivedParamMap.get("encryptedKey").toString(), serverPrivateKey);
        // AES密钥对解密参数解密
        String decryptData = AESUtils.decrypt(receivedParamMap.get("encryptedData").toString(), aesKey);
        return decryptData;
    }


}
