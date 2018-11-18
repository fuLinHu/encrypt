package com.spring.encrypt.encryptUtil;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESUtil {
    static String  DATA="付林虎";
    /*
     * 生成密钥
     */
    public static byte[] initKey() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }


    /*
     * DES 加密
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception{
        SecretKey secretKey = new SecretKeySpec(key, "DES");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherBytes = cipher.doFinal(data);
        return cipherBytes;
    }


    /*
     * DES 解密
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception{
        SecretKey secretKey = new SecretKeySpec(key, "DES");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plainBytes = cipher.doFinal(data);
        return plainBytes;
    }

    //Test
    public static void main(String[] args) throws Exception {
        byte[] desKey = DESUtil.initKey();
        System.out.println("DES KEY : " + Base64.encodeBase64String(desKey));
        byte[] desResult = DESUtil.encrypt(DATA.getBytes(), desKey);
        System.out.println(">>>DES 加密结果>>>" + Base64.encodeBase64String(desResult));

        byte[] desPlain = DESUtil.decrypt(desResult, desKey);
        System.out.println(">>>DES 解密结果>>>" + new String(desPlain));
    }
}
