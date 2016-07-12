package test;

import java.io.ByteArrayOutputStream;  
import java.lang.reflect.Method;  
import java.nio.charset.Charset;  
import java.security.InvalidKeyException;  
import java.security.KeyFactory;  
import java.security.NoSuchAlgorithmException;  
import java.security.PrivateKey;  
import java.security.PublicKey;  
import java.security.interfaces.RSAPrivateKey;  
import java.security.interfaces.RSAPublicKey;  
import java.security.spec.InvalidKeySpecException;  
import java.security.spec.PKCS8EncodedKeySpec;  
import java.security.spec.X509EncodedKeySpec;  
import javax.crypto.BadPaddingException;  
import javax.crypto.Cipher;  
import javax.crypto.IllegalBlockSizeException;  
import javax.crypto.NoSuchPaddingException;  
  
/** 
 *RSA
 *  
 */  
public class RSAUtil {  
	 private static int MAXENCRYPTSIZE = 117;  
	    private static int MAXDECRYPTSIZE = 128;  
	  
	    /** 
	     * @param publicKeyByte 
	     * @return RSAPublicKey 
	     * @throws NoSuchAlgorithmException 
	     * @throws InvalidKeySpecException 
	     */  
	    public static RSAPublicKey getPublicKey(byte[] publicKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException{  
	        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKeyByte);          
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
	        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509);  
	        return publicKey;         
	    }  
	  
	    public static RSAPrivateKey getPrivateKey(byte[] privateKeyByte) throws InvalidKeySpecException, NoSuchAlgorithmException {  
	        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);  
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
	        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);  
	    }  
	  
	  
	    /** 
	     * encrypt 
	     * @param source 
	     * @param publicKey 
	     * @return Bute[] encryptData 
	     * @throws Exception 
	     */  
	    public static byte[] encrypt(PublicKey publicKey, byte[] source)  
	            throws Exception {  
	        try {  
	            //此处填充方式选择部填充 NoPadding，当然模式和填充方式选择其他的，在Java端可以正确加密解密，  
	            //但是解密后的密文提交给C#端，解密的得到的数据将产生乱码  
	            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");  
	            cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
	            int length = source.length;  
	            int offset = 0;  
	            byte[] cache;  
	            ByteArrayOutputStream outStream = new ByteArrayOutputStream();  
	            int i = 0;  
	            while (length - offset > 0) {  
	                if (length - offset > MAXENCRYPTSIZE) {  
	                    cache = cipher.doFinal(source, offset, MAXENCRYPTSIZE);  
	                } else {  
	                    cache = cipher.doFinal(source, offset, length - offset);  
	                }  
	                outStream.write(cache, 0, cache.length);  
	                i++;  
	                offset = i * MAXENCRYPTSIZE;  
	            }  
	            return outStream.toByteArray();  
	        } catch (NoSuchAlgorithmException e) {  
	            e.printStackTrace();  
	        } catch (NoSuchPaddingException e) {  
	            e.printStackTrace();  
	        } catch (InvalidKeyException e) {  
	            e.printStackTrace();  
	        } catch (IllegalBlockSizeException e) {  
	            e.printStackTrace();  
	        } catch (BadPaddingException e) {  
	            e.printStackTrace();  
	        }  
	        return null;  
	    }  
	  
	    /**RSA decrypt 
	     * @param privateKey 
	     * @param encryptData 
	     * @return decryptData 
	     * @throws IllegalBlockSizeException 
	     * @throws BadPaddingException 
	     * @throws InvalidKeyException 
	     * @throws NoSuchAlgorithmException 
	     * @throws NoSuchPaddingException 
	     */  
	    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData)  
	            throws IllegalBlockSizeException, BadPaddingException,  
	            InvalidKeyException, NoSuchAlgorithmException,  
	            NoSuchPaddingException {  
	        //此处模式选择与加密对应，但是需要添加第二个参数new org.bouncycastle.jce.provider.BouncyCastleProvider()  
	        //若不添加第二个参数的话，解密后的数据前面出现大段空格符  
	        Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());  
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
	  
	        int length = encryptData.length;  
	        int offset = 0;  
	        int i = 0;  
	        byte[] cache;  
	        ByteArrayOutputStream outStream = new ByteArrayOutputStream();  
	        while (length - offset > 0) {  
	            if (length - offset > MAXDECRYPTSIZE) {  
	                cache = cipher.doFinal(encryptData, offset, MAXDECRYPTSIZE);  
	            } else {  
	                cache = cipher.doFinal(encryptData, offset, length - offset);  
	            }  
	            outStream.write(cache, 0, cache.length);  
	            i++;  
	            offset = i * MAXDECRYPTSIZE;  
	        }  
	        return outStream.toByteArray();  
	    }  
	  
	    /** 
	     * base64编码 
	     *  
	     * @param input 
	     * @return output with base64 encoded 
	     * @throws Exception 
	     */  
	    public static String encodeBase64(byte[] input) throws Exception {  
	        Class clazz = Class  
	                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");  
	        Method mainMethod = clazz.getMethod("encode", byte[].class);  
	        mainMethod.setAccessible(true);  
	        Object retObj = mainMethod.invoke(null, new Object[] { input });  
	        return (String) retObj;  
	    }  
	  
	    /** 
	     * base64解码 
	     *  
	     * @param input 
	     * @return 
	     * @throws Exception 
	     */  
	    public static byte[] decodeBase64(String input) throws Exception {  
	        Class clazz = Class  
	                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");  
	        Method mainMethod = clazz.getMethod("decode", String.class);  
	        mainMethod.setAccessible(true);  
	        Object retObj = mainMethod.invoke(null, input);  
	        return (byte[]) retObj;  
	    }  
//	      
//	    public static void main(String[] args) throws Exception {  
//	        RSAPublicKey rsaPublicKey = getPublicKey(decodeBase64("MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCzoQTA/zgahiaytyggCLoodqhuG8gRUXypUt+9HAtPsNhRHC2ksQazS8DnyyrfgrmPfv///AHURL2itn7L1gfrVcm7QDLwM/gXCjUV5lkRrlp7SDF6yxrF00PLWOvAae1eEmmg9ucymEjwq2pzEVMJyWslJdXjvYOSDstUMbqCtQIBAw=="));  
//	        byte[] encryptData = encrypt(rsaPublicKey, "成功了...".getBytes(Charset.forName("utf-8")));  
//	        System.out.println("密文：\n" + encodeBase64(encryptData));  
//	        RSAPrivateKey privateKey = getPrivateKey(decodeBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALOhBMD/OBqGJrK3KCAIuih2qG4byBFRfKlS370cC0+w2FEcLaSxBrNLwOfLKt+CuY9+///8AdREvaK2fsvWB+tVybtAMvAz+BcKNRXmWRGuWntIMXrLGsXTQ8tY68Bp7V4SaaD25zKYSPCranMRUwnJayUl1eO9g5IOy1QxuoK1AgEDAoGAd8Ct1f96vFlvIc9wFVsmxaRwSWfatjZTG4yVKL1c38s64L1zwyCvIjKAmodx6lcmX6n///1WjYMpFyRUh+QFRm9H60Ger3PfUII4epgVHqX20aRWy32cmW3Gp+r04p7ENja/Jey6HsdXb7Q32fdZKsLZOO2lvNdUu/5+LsP6wTMCQQDsFcBU1JFA3l6vZyi3b+nzZgoaCo6kMTTG4i/S/kf8cVPw5jaEVGUMhsXPkicWXNpppXNU4yA4gbNRN2XXnsjnAkEAwsgaCPBXxUq/l3k1Ssl5wgI2t6S66n6q57efpX4kf1W4z2Sxj3ufYL8DTYSFB/BvO3/cbHooQgLEv9aoNCOYAwJBAJ1j1Y3jC4CUPx+aGyT1RqJEBrwHCcLLeISWyoyphVL2N/XuzwLi7ghZ2TUMGg7okZvDojiXatBWd4t6Q+UUhe8CQQCB2rwF9Y/Y3H+6UM4x26aBVs8lGHycVHHvz7/DqW2qOSXfmHZfp7+V1KzeWFiv9Z98/+hIUXAsAdh/5HAiwmVXAkEAmo9GTWqbRP6BU75MPPnL42zq/4cQBI4yya03NDZjU1lwA2YvmFzJaM4mVmrsxNeDv6qY7Ibl/GDwIbAUaEHaAA=="));  
//	        System.out.println("解密后数据：" + new String(decrypt(privateKey, encryptData),"utf-8"));  
//	    }  
}  