//package com.example.qr_utils_box;
//
///**
// * @author : 其然乐衣Letitbe
// * @date : 2025/10/12
// */
////1、转转发送请求
////        合作伙伴公钥：对AES key加密，得到randomKey
////        转转私钥：对参数签名，得到sign
////
////        2、合作伙伴解密请求
////        转转公钥：校验签名sign  (rsaCheckContent方法)
////        合作伙伴私钥：解密randomKey，（rsaDecryptByPrivate 方法）得到AES key，
////        使用AES key，解密业务参数 （aesDecrypt 方法）
////
////        3、合作伙伴响应请求（类似）
////
////        4、转转解密响应请求（类似）
////
////
//
//import com.alibaba.fastjson.JSON;
//import com.alibaba.fastjson.JSONObject;
//import org.apache.commons.codec.DecoderException;
//import org.apache.commons.codec.binary.Hex;
//import org.apache.commons.lang3.StringUtils;
//import org.bouncycastle.util.encoders.DecoderException;
//import org.junit.platform.commons.util.StringUtils;
//
//import javax.crypto.Cipher;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.GeneralSecurityException;
//import java.security.KeyFactory;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.Signature;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.*;
//
///**
// * @author Rouse
// * @date: 2022/4/15 14:14
// * @description: RSA加解密demo
// */
//class Demo {
//
//    //转转RSA公钥
//    static String zzRsaPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDH5RuutBp5uShEwjg2vg3YWDFo4tgbzzN+U08VFzm8X14C1wM0nKt8HulXEWpLKYNPKEfw62RnMUUgHXcOKwocOIcAb+cREtMNymaS9o6LPo+u9hs5Qe045mD0b9jkEVAjKvaubDzbx2eT/6Z7WuYOL49lk7TDnJSsWcEuwdgAyQIDAQAB";
//
//    //转转RSA私钥（私钥不公布，这里只是测试场景）
//    static String zzRsaPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMflG660Gnm5KETCODa+DdhYMWji2BvPM35TTxUXObxfXgLXAzScq3we6VcRakspg08oR/DrZGcxRSAddw4rChw4hwBv5xES0w3KZpL2jos+j672GzlB7TjmYPRv2OQRUCMq9q5sPNvHZ5P/pnta5g4vj2WTtMOclKxZwS7B2ADJAgMBAAECgYAwFofAUYeE/OwZDngjgzklcKICT4AZwJDstPHzavDyxiaBnGQjBgWjCHSuA3yEtGnoYxJbfOVchdfRUAVSHTyC/Ka9EUVVu0xlV7kKZwdq8UqCR+wbvfqgC6w4Je+u+dRYi3/ETo7ZNlOSRlBp9ccmlR2XAR65gsBXOXrceIfJuQJBAOM24YYK4x8t/hgAbwIznPCiGDitFkNkvDiPtq7NJkkMKXPU3/PPx99o4a13FxvlEGh8svLKsAv8Qkv/+ZU3dg8CQQDhODD4LMxrUBiwxN4qK0pkT+4O3v4Z76CGxzWZsF/fZhFsscVnldZpfgVk0Ice/33awAO9TUby3fGKyCh8izOnAkEA2y9VDU6xXKGsjZDVhYUurz9fKEVoxaiGnfWdIDFM7oip8FB5niRhxpXRptnMVB973Z/1rJt0iotVlSUgqh5vZwJANqzThowpnCu3ssI4RPh5eNzGqCmOenFoARA/fO4KeEtpE4Acskb35GhJmu3cv7O6s+5FeiFWhgNHbi+lVIbepQJABOisvNOnajjSsjwPDniXwyhHO6GWDPKV5DvLOlbRR5qmko27h18RE7UocMJmcQsLfAboFPOe1B5Zp84Itim1TQ==";
//
//    //资方RSA公钥
//    static String partnerPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPiNEwj12Fo0mcQuIfEBEd1I1IjeruegKCrEBfmB0eYyE5G9RhISfF4554Ctsoz+ThKq2NqlSc6cJ/0IeRJ4PpslIEnfXbAt5oqZ3/KYuEGIDwReztfj47QI9GvuSccxrscH6aCpnxf7J8Ux8S8UFbxpLnwpyriwgzQhxdoIYj6wIDAQAB";
//
//    //资方RSA私钥（私钥不公布，这里只是测试场景）
//    static String partnerPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM+I0TCPXYWjSZxC4h8QER3UjUiN6u56AoKsQF+YHR5jITkb1GEhJ8XjnngK2yjP5OEqrY2qVJzpwn/Qh5Eng+myUgSd9dsC3mipnf8pi4QYgPBF7O1+PjtAj0a+5JxzGuxwfpoKmfF/snxTHxLxQVvGkufCnKuLCDNCHF2ghiPrAgMBAAECgYEAmtdIxMNikq/G3xij32s8ahZJJ2YDb9SGhPqBuREkQKTTh+l0ptd29lWiyYvIAoZCDaGrBbSdFsnuPTDXxPxHlT895Qe5H984fltB1+bA3kXRh85KOFi7yNxI+i+OLjR4XZKUdlkKqDBcT8PDWbZD6hL66cqCmJyKdDq65iYV11ECQQD6ZhlPoGyA6h/yLsBKwuGFrrLfUlfDmPffCjj603dEhsKeb5+BPaGFWdBXz1EZCbrZ1CWB5swOBB0rKaruy4CzAkEA1C1BuEdEPAQ+eirxRu9Eg6ZaR926DZ3zi2Tiacdo56ff8Vh8Qk9GWuA1KBBfsmCJeGbska46gbeTcobSP6h76QJASzvgAP+3eihePtrzJcNWFV9/GQBZpEhSuW4N3rcoz6sZ0JbDOwa0gCeTJL8Co947iPVn65bX2qI7zVswo5z7ZwJAS5o0qKz8K0Z33KAgiN4I08AauzDOcrutZCX2ZyqevqyapyyYWihVMVxilHwBHVY4paZG9UHXpxD6gPx5PiWSwQJAHT97FvM8S2Kpzbr+mDdrz7gVBf9KFNa7sDYFE/HUsJvwQ1l0h6OS0PGqI7n2PPQG8NETQgG5srU3eEW+vFX9XA==";
//
//    private static final String ALGORITHM = "RSA";
//
//    public static void main(String[] args) throws Exception {
//        //模拟转转对请求参数加密
//        //1 合作伙伴公钥：对AES key加密，得到randomKey（随请求带出）
//        //2 转转私钥：对参数签名，得到sign（随请求带出）
//        String str = encrypted();
//        System.out.println("加密后：" + str);
//
//        //模拟资方解密转转的请求参数
//        //3 转转公钥：校验签名（sign）
//        //4 合作伙伴私钥：解密randomKey，得到AES key
//        //5 使用AES key，解密业务参数
//        String t = decrypted(str);
//        System.out.println("解密后：" + t);
//
//        //资方对响应参数、各类回调参数加密同理
//    }
//
//
//
//    /**
//     * 对请求参数解密
//     *
//     * @param postStr
//     * @return
//     * @throws Exception
//     */
//    static String decrypted(String postStr) throws Exception {
//        //资方接收到转转的参数
//        Map<String, Object> receivedParamMap = JSONObject.parseObject(postStr).getInnerMap();
//        String sign = (String) receivedParamMap.get("sign");
//        receivedParamMap.remove("sign");
//        Map<String, Object> receivedParaTreeMap = new TreeMap(receivedParamMap);
//        // salt值 默认：ps&d$
//        String sortParamStr = sortParams(receivedParaTreeMap, "ps&d$");
//
//        //签名校验，根据结果决定流程
//        boolean f = rsaCheckContent(sortParamStr, sign, zzRsaPublicKey);
//
//        //获取DES decryptKey（桔子RSA私钥解密）
//        String aesDecryptKey = rsaDecryptByPrivate(partnerPrivateKey, (String) receivedParamMap.get("randomKey"));
//
//        return aesDecrypt(aesDecryptKey, (String) receivedParamMap.get("bizContent"));
//    }
//
//
//    /**
//     * 对请求参数加密
//     *
//     * @return
//     * @throws Exception
//     */
//    static String encrypted() throws Exception {
//        RequestProtocol rp = new RequestProtocol();
//        rp.setAppId("zz-api");
//        rp.setTimestamp(System.currentTimeMillis());
//
//        //AES secretKey（随机生成）
//        RandomStringUtils.randomNumeric(32);
//        String aesEncryptKey = "96695747908994725758890194799371";
//
//        //业务参数 bizContent
//        String bizContent = "{\n" +
//                "    \"name\":\"我是转转\",\n" +
//                "    \"contractType\": \"AUTH\",\n" +
//                "    \"zzOpenId\": \"105ee4b8c085dc2e02259d62376b202de27e95ee5f08f8638ea3fdec2833dc0f\"\n" +
//                "}";
//
//        //AES算法加密业务参数
//        String encryptedBizContent = aesEncrypt(aesEncryptKey, bizContent);
//        rp.setBizContent(encryptedBizContent);
//
//        //使用合作伙伴RSA公钥加密AES secretKey
//        String randomKey = rsaEncryptByPublic(partnerPublicKey, aesEncryptKey);
//        rp.setRandomKey(randomKey);
//
//        Map<String, Object> requestMap = JSONObject.parseObject(JSON.toJSONString(rp)).getInnerMap();
//
//        //使用转转RSA私钥对参数签名（salt值 双方约定，默认：ps&d$）
//        String sign = rsaSign(sortParams(new TreeMap(requestMap), "ps&d$"), zzRsaPrivateKey);
//        requestMap.put("sign", sign);
//
//        //模拟转转http发送的请求包
//        return JSON.toJSONString(requestMap);
//    }
//
//    /**
//     * RSA 私钥解密
//     *
//     * @param encodedKey
//     * @param content
//     * @return
//     * @throws Exception
//     */
//    public static String rsaDecryptByPrivate(String encodedKey, String content) throws Exception {
//        if (StringUtils.isEmpty(encodedKey)) {
//            throw new Exception("解密密钥为空");
//        }
//        if (StringUtils.isEmpty(content)) {
//            throw new Exception("待解密数据为空");
//        }
//        PrivateKey key = null;
//        try {
//            key = getPrivateKeyFromPKCS8("RSA", encodedKey);
//        } catch (Exception var5) {
//            throw new Exception("解密异常", var5);
//        }
//        return decrypt(key, content);
//    }
//
//    public static String encrypt(PublicKey publicKey, String plainText) throws Exception {
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
//        return Base64.getEncoder().encodeToString(encryptedBytes);
//    }
//
//    public static String decrypt(PrivateKey privateKey, String encryptedText) throws Exception {
//        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8));
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
//        return new String(decryptedBytes, StandardCharsets.UTF_8);
//    }
//
//    /**
//     * RSA签名 privateKey
//     *
//     * @param content
//     * @param privateKey
//     * @return
//     * @throws Exception
//     */
//    public static String rsaSign(String content, String privateKey) throws Exception {
//        try {
//            PrivateKey priKey = getPrivateKeyFromPKCS8("RSA", privateKey);
//            Signature signature = Signature.getInstance("SHA256WithRSA");
//            signature.initSign(priKey);
//            signature.update(content.getBytes(StandardCharsets.UTF_8));
//            return Base64.getEncoder().encodeToString(signature.sign());
//        } catch (Exception var5) {
//            throw new Exception("RSA签名异常", var5);
//        }
//    }
//
//    /**
//     * RSA签名 publicKey
//     *
//     * @param content
//     * @param sign
//     * @param publicKey
//     * @return
//     * @throws Exception
//     */
//    public static boolean rsaCheckContent(String content, String sign, String publicKey) throws Exception {
//        try {
//            PublicKey pubKey = getPublicKeyFromX509("RSA", publicKey);
//            Signature signature = Signature.getInstance("SHA256WithRSA");
//            signature.initVerify(pubKey);
//            signature.update(content.getBytes(StandardCharsets.UTF_8));
//            return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
//        } catch (Exception var6) {
//            throw new Exception("RSA签名验证错误,响应签名:" + sign, var6);
//        }
//    }
//
//    /**
//     * RSA 公钥加密
//     *
//     * @param encodedKey
//     * @param content
//     * @return
//     * @throws Exception
//     */
//    public static String rsaEncryptByPublic(String encodedKey, String content) throws Exception {
//        if (StringUtils.isEmpty(encodedKey)) {
//            throw new Exception("密钥为空");
//        } else if (StringUtils.isEmpty(content)) {
//            throw new Exception("待加密数据为空");
//        } else {
//            PublicKey key = null;
//            try {
//                key = getPublicKeyFromX509("RSA", encodedKey);
//            } catch (Exception var5) {
//                throw new Exception("加密异常", var5);
//            }
//            return encrypt(key, content);
//        }
//    }
//
//
//    /**
//     * AES加密
//     *
//     * @param key
//     * @param data
//     * @return
//     * @throws GeneralSecurityException
//     */
//    public static String aesEncrypt(String key, String data) throws GeneralSecurityException, DecoderException {
//        if (key != null && data != null) {
//            byte[] raw = Hex.decodeHex(key.toCharArray());
//            SecretKeySpec skySpec = new SecretKeySpec(raw, "AES");
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            cipher.init(1, skySpec, new IvParameterSpec(new byte[16]));
//            return Hex.encodeHexString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
//        } else {
//            return null;
//        }
//    }
//
//    /**
//     * AES解密
//     *
//     * @param key
//     * @param encrypted
//     * @return
//     * @throws GeneralSecurityException
//     * @throws DecoderException
//     */
//    public static String aesDecrypt(String key, String encrypted) throws GeneralSecurityException, DecoderException {
//        if (key != null && encrypted != null) {
//            byte[] raw = Hex.decodeHex(key.toCharArray());
//            SecretKeySpec sKeySpec = new SecretKeySpec(raw, "AES");
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            cipher.init(2, sKeySpec, new IvParameterSpec(new byte[16]));
//            byte[] original = cipher.doFinal(Hex.decodeHex(encrypted.toCharArray()));
//            return new String(original, StandardCharsets.UTF_8);
//        } else {
//            return null;
//        }
//    }
//
//    public static PublicKey getPublicKeyFromX509(String algorithm, String encodedKey) throws Exception {
//        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
//        byte[] key = Base64.getDecoder().decode(encodedKey);
//        return keyFactory.generatePublic(new X509EncodedKeySpec(key));
//    }
//
//    public static PrivateKey getPrivateKeyFromPKCS8(String algorithm, String encodedKey) throws Exception {
//        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
//        byte[] key = Base64.getDecoder().decode(encodedKey);
//        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
//    }
//
//    /**
//     * 对参数排序
//     *
//     * @param sortedParams
//     * @param salt
//     * @return
//     */
//    public static String sortParams(Map<String, Object> sortedParams, String salt) {
//        List<String> keys = new ArrayList(sortedParams.keySet());
//        Collections.sort(keys);
//        StringBuilder content = new StringBuilder();
//        int index = 0;
//        int i = 0;
//        for (int size = keys.size(); i < size; ++i) {
//            String key = (String) keys.get(i);
//            Object value = sortedParams.get(key);
//            if (!Objects.isNull(value) && (!(value instanceof List) || !((List) value).isEmpty()) && (!(value instanceof String) || !StringUtils.isBlank((String) value))) {
//                content.append((index == 0 ? "" : "&") + key + "=" + value);
//                ++index;
//            }
//        }
//        if (StringUtils.isNotBlank(salt)) {
//            content.append("&key=").append(salt);
//        }
//        return content.toString();
//    }
//
//    static class RequestProtocol {
//        private String appId;
//        private Long timestamp;
//        private String randomKey;
//        private String sign;
//        private String bizContent;
//
//        public String getAppId() {
//            return appId;
//        }
//
//        public void setAppId(String appId) {
//            this.appId = appId;
//        }
//
//        public Long getTimestamp() {
//            return timestamp;
//        }
//
//        public void setTimestamp(Long timestamp) {
//            this.timestamp = timestamp;
//        }
//
//        public String getRandomKey() {
//            return randomKey;
//        }
//
//        public void setRandomKey(String randomKey) {
//            this.randomKey = randomKey;
//        }
//
//        public String getSign() {
//            return sign;
//        }
//
//        public void setSign(String sign) {
//            this.sign = sign;
//        }
//
//        public String getBizContent() {
//            return bizContent;
//        }
//
//        public void setBizContent(String bizContent) {
//            this.bizContent = bizContent;
//        }
//    }
//}
//
//
//
//
//
////AES key生成类
////生成随机AES秘钥aesEncryptKey = RandomStringUtils.randomNumeric(32);
//
//public class RandomStringUtils {
//
//    public static void main(String[] args) {
//        String esEncryptKey = RandomStringUtils.randomNumeric(32);
//        System.out.println(esEncryptKey);
//    }
//    private static final Random RANDOM = new Random();
//
//    private RandomStringUtils() {
//    }
//
//    public static String randomNumeric(int count) {
//        return random(count, false, true);
//    }
//
//    public static String random(int count, boolean letters, boolean numbers) {
//        return random(count, 0, 0, letters, numbers);
//    }
//
//    public static String random(int count, int start, int end, boolean letters, boolean numbers) {
//        return random(count, start, end, letters, numbers, (char[])null, RANDOM);
//    }
//
//    public static String random(int count, int start, int end, boolean letters, boolean numbers, char[] chars, Random random) {
//        if (count == 0) {
//            return "";
//        } else if (count < 0) {
//            throw new IllegalArgumentException("Requested random string length " + count + " is less than 0.");
//        } else if (chars != null && chars.length == 0) {
//            throw new IllegalArgumentException("The chars array must not be empty");
//        } else {
//            if (start == 0 && end == 0) {
//                if (chars != null) {
//                    end = chars.length;
//                } else if (!letters && !numbers) {
//                    end = 2147483647;
//                } else {
//                    end = 123;
//                    start = 32;
//                }
//            } else if (end <= start) {
//                throw new IllegalArgumentException("Parameter end (" + end + ") must be greater than start (" + start + ")");
//            }
//
//            char[] buffer = new char[count];
//            int gap = end - start;
//
//            while(true) {
//                while(true) {
//                    while(count-- != 0) {
//                        char ch;
//                        if (chars == null) {
//                            ch = (char)(random.nextInt(gap) + start);
//                        } else {
//                            ch = chars[random.nextInt(gap) + start];
//                        }
//
//                        if (letters && Character.isLetter(ch) || numbers && Character.isDigit(ch) || !letters && !numbers) {
//                            if (ch >= '\udc00' && ch <= '\udfff') {
//                                if (count == 0) {
//                                    ++count;
//                                } else {
//                                    buffer[count] = ch;
//                                    --count;
//                                    buffer[count] = (char)('\ud800' + random.nextInt(128));
//                                }
//                            } else if (ch >= '\ud800' && ch <= '\udb7f') {
//                                if (count == 0) {
//                                    ++count;
//                                } else {
//                                    buffer[count] = (char)('\udc00' + random.nextInt(128));
//                                    --count;
//                                    buffer[count] = ch;
//                                }
//                            } else if (ch >= '\udb80' && ch <= '\udbff') {
//                                ++count;
//                            } else {
//                                buffer[count] = ch;
//                            }
//                        } else {
//                            ++count;
//                        }
//                    }
//
//                    return new String(buffer);
//                }
//            }
//        }
//    }
//}
//
//
//
//
//
//
//
//
//
//
//
//
//
