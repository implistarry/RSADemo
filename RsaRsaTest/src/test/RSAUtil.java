package test;

import java.io.ByteArrayOutputStream;  
import java.io.UnsupportedEncodingException;
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

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
  
/** 
 *RSA
 *  
 */  
public class RSAUtil {  
	    private static int MAXENCRYPTSIZE = 117;  
	    private static int MAXDECRYPTSIZE = 128;  
	    
	    
	    /**
		 * 解密
		 * @param privateKey
		 * @param encryptContent
		 * @return
		 */
		public static String decrypt(String privateKey,String encryptContent){
			 String txt=null;
			try {
			 byte[] encryptData2=RSAUtil.decodeBase64(encryptContent);		
			 byte[] pk = RSAUtil.decodeBase64(privateKey);
			 RSAPrivateKey privateKeyf = RSAUtil.getPrivateKey(pk);  	
			 txt = new String(RSAUtil.decrypt(privateKeyf, encryptData2),"utf-8");
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			 		
			return new String(txt);
			
		}
		
		/**
		 * 加密方法
		 * @param publicKey
		 * @param content
		 * @return
		 */
		public static String encrypt(String publicKey,String content){
			 RSAPublicKey rsaPublicKey;
			 String miTxt="";
			try {
				rsaPublicKey = RSAUtil.getPublicKey(RSAUtil.decodeBase64(publicKey));
				 byte[] encryptData = RSAUtil.encrypt(rsaPublicKey,content.getBytes(Charset.forName("utf-8")));  
				  miTxt = RSAUtil.encodeBase64(encryptData);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}	
			return miTxt;
		}
	  
	    /** 
	     * @param publicKeyByte 
	     * @return RSAPublicKey 
	     * @throws NoSuchAlgorithmException 
	     * @throws InvalidKeySpecException 
	     */  
		private static RSAPublicKey getPublicKey(byte[] publicKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException{  
	        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKeyByte);          
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
	        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509);  
	        return publicKey;         
	    }  
	  
		private static RSAPrivateKey getPrivateKey(byte[] privateKeyByte) throws InvalidKeySpecException, NoSuchAlgorithmException {  
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
		private static byte[] encrypt(PublicKey publicKey, byte[] source)  
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
		private static byte[] decrypt(PrivateKey privateKey, byte[] encryptData)  
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
		private static String encodeBase64(byte[] input) throws Exception { 
//	        Class clazz = Class.forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");  
//	        Method mainMethod = clazz.getMethod("encode", byte[].class);  
//	        mainMethod.setAccessible(true);  
//	        Object retObj = mainMethod.invoke(null, new Object[] { input });  
//	        return (String) retObj;  
	    	return Base64.encode(input);
	    }  
	  
	    /** 
	     * base64解码 
	     *  
	     * @param input 
	     * @return 
	     * @throws Exception 
	     */  
		private static byte[] decodeBase64(String input)  {  
//	        Class clazz = Class.forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");  
//	        Method mainMethod = clazz.getMethod("decode", String.class);  
//	        mainMethod.setAccessible(true);  
//	        Object retObj = mainMethod.invoke(null, input);  
//	        return (byte[]) retObj;  
	    	byte[] aa = Base64.decode(input);
	        return aa;
	    }  
 
}  
