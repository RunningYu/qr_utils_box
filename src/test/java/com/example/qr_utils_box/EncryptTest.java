package com.example.qr_utils_box;

import com.example.qr_utils_box.utils.encrypt.RsaAesMixedUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author : 其然乐衣Letitbe
 * @date : 2025/10/18
 */
@SpringBootTest
public class EncryptTest {

    // 客户端RSA公钥
    final static String clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDH5RuutBp5uShEwjg2vg3YWDFo4tgbzzN+U08VFzm8X14C1wM0nKt8HulXEWpLKYNPKEfw62RnMUUgHXcOKwocOIcAb+cREtMNymaS9o6LPo+u9hs5Qe045mD0b9jkEVAjKvaubDzbx2eT/6Z7WuYOL49lk7TDnJSsWcEuwdgAyQIDAQAB";

    // 客户端RSA私钥（私钥不公布，这里只是测试场景）
    final static String clientPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMflG660Gnm5KETCODa+DdhYMWji2BvPM35TTxUXObxfXgLXAzScq3we6VcRakspg08oR/DrZGcxRSAddw4rChw4hwBv5xES0w3KZpL2jos+j672GzlB7TjmYPRv2OQRUCMq9q5sPNvHZ5P/pnta5g4vj2WTtMOclKxZwS7B2ADJAgMBAAECgYAwFofAUYeE/OwZDngjgzklcKICT4AZwJDstPHzavDyxiaBnGQjBgWjCHSuA3yEtGnoYxJbfOVchdfRUAVSHTyC/Ka9EUVVu0xlV7kKZwdq8UqCR+wbvfqgC6w4Je+u+dRYi3/ETo7ZNlOSRlBp9ccmlR2XAR65gsBXOXrceIfJuQJBAOM24YYK4x8t/hgAbwIznPCiGDitFkNkvDiPtq7NJkkMKXPU3/PPx99o4a13FxvlEGh8svLKsAv8Qkv/+ZU3dg8CQQDhODD4LMxrUBiwxN4qK0pkT+4O3v4Z76CGxzWZsF/fZhFsscVnldZpfgVk0Ice/33awAO9TUby3fGKyCh8izOnAkEA2y9VDU6xXKGsjZDVhYUurz9fKEVoxaiGnfWdIDFM7oip8FB5niRhxpXRptnMVB973Z/1rJt0iotVlSUgqh5vZwJANqzThowpnCu3ssI4RPh5eNzGqCmOenFoARA/fO4KeEtpE4Acskb35GhJmu3cv7O6s+5FeiFWhgNHbi+lVIbepQJABOisvNOnajjSsjwPDniXwyhHO6GWDPKV5DvLOlbRR5qmko27h18RE7UocMJmcQsLfAboFPOe1B5Zp84Itim1TQ==";

    // 服务端RSA公钥
    final static String serverPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPiNEwj12Fo0mcQuIfEBEd1I1IjeruegKCrEBfmB0eYyE5G9RhISfF4554Ctsoz+ThKq2NqlSc6cJ/0IeRJ4PpslIEnfXbAt5oqZ3/KYuEGIDwReztfj47QI9GvuSccxrscH6aCpnxf7J8Ux8S8UFbxpLnwpyriwgzQhxdoIYj6wIDAQAB";

    // 服务端RSA私钥（私钥不公布，这里只是测试场景）
    final static String serverPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM+I0TCPXYWjSZxC4h8QER3UjUiN6u56AoKsQF+YHR5jITkb1GEhJ8XjnngK2yjP5OEqrY2qVJzpwn/Qh5Eng+myUgSd9dsC3mipnf8pi4QYgPBF7O1+PjtAj0a+5JxzGuxwfpoKmfF/snxTHxLxQVvGkufCnKuLCDNCHF2ghiPrAgMBAAECgYEAmtdIxMNikq/G3xij32s8ahZJJ2YDb9SGhPqBuREkQKTTh+l0ptd29lWiyYvIAoZCDaGrBbSdFsnuPTDXxPxHlT895Qe5H984fltB1+bA3kXRh85KOFi7yNxI+i+OLjR4XZKUdlkKqDBcT8PDWbZD6hL66cqCmJyKdDq65iYV11ECQQD6ZhlPoGyA6h/yLsBKwuGFrrLfUlfDmPffCjj603dEhsKeb5+BPaGFWdBXz1EZCbrZ1CWB5swOBB0rKaruy4CzAkEA1C1BuEdEPAQ+eirxRu9Eg6ZaR926DZ3zi2Tiacdo56ff8Vh8Qk9GWuA1KBBfsmCJeGbska46gbeTcobSP6h76QJASzvgAP+3eihePtrzJcNWFV9/GQBZpEhSuW4N3rcoz6sZ0JbDOwa0gCeTJL8Co947iPVn65bX2qI7zVswo5z7ZwJAS5o0qKz8K0Z33KAgiN4I08AauzDOcrutZCX2ZyqevqyapyyYWihVMVxilHwBHVY4paZG9UHXpxD6gPx5PiWSwQJAHT97FvM8S2Kpzbr+mDdrz7gVBf9KFNa7sDYFE/HUsJvwQ1l0h6OS0PGqI7n2PPQG8NETQgG5srU3eEW+vFX9XA==";

    @Test
    public void rsaAesTest() throws Exception {
        String str = "123456";
        String encrypt = RsaAesMixedUtils.encrypt(str, clientPrivateKey, serverPublicKey, "salt");
        System.out.println(encrypt);
//        String decrypt = RsaAesMixedUtils.decrypt(encrypt);
//        System.out.println(decrypt);
    }
}
