package com.shank.budget.config;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public enum AESUtils {
    ;

    private static final String ENCRYPTION_KEY = "E71FDD277741D2FC8A710ADA5DD4E5D6";
    private static final String ENCRYPTION_IV = "0000000000000000";

    public static void main(String[] args) {

        String str = "123456";

        System.out.println("original text="+str);

        String encyStr = encrypt(str);
        System.out.println("encyStr="+encyStr);

        String decryptStr = decrypt(encyStr);
        System.out.println("decryptStr="+decryptStr);
    }

    public static String encrypt(String src) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, makeKey(), makeIv());
            return Base64.encodeBase64String(cipher.doFinal(src.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(String src) {
        String decrypted = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, makeKey(), makeIv());
            decrypted = new String(cipher.doFinal(Base64.decodeBase64(src)));
        } catch (Exception e) {
            throw new RuntimeException("Invalid Id");
        }
        return decrypted;
    }

    static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // e.printStackTrace();
        }
        return null;
    }

    static Key makeKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(ENCRYPTION_KEY.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            // e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // e.printStackTrace();
        }

        return null;
    }
}