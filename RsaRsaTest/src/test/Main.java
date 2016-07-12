package test;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

public class Main {


	public static void main(String[] args){
		 try {
			 String oldTxt = "hello哈哈";//原文
			 System.out.println("原文：\n" + oldTxt);  
			 
			 RSAPublicKey rsaPublicKey = RSAUtil.getPublicKey(RSAUtil.decodeBase64(Key.PublicKey));	
			 
			 byte[] encryptData = RSAUtil.encrypt(rsaPublicKey,oldTxt.getBytes(Charset.forName("utf-8")));  
			 String miTxt = RSAUtil.encodeBase64(encryptData);//密文
			 System.out.println("密文：\n" + miTxt);  
//			 
			 
			 
			 
			 byte[] encryptData2=RSAUtil.decodeBase64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARXGh3iyJfiDoFpLy1yDEU7U8=");		
			 RSAPrivateKey privateKey = RSAUtil.getPrivateKey(RSAUtil.decodeBase64(Key.PrivateKey));  		      
			 String txt = new String(RSAUtil.decrypt(privateKey, encryptData2),"utf-8");
			 byte[] aa1=RSAUtil.decrypt(privateKey, encryptData2);
//			byte[] aa= Base64.decode(RSAUtil.decrypt(privateKey, encryptData2));
			
			 System.out.println("解密：\n" + new String(aa1));
			 
		 }catch (Exception e) {
			e.printStackTrace();
		}  
	      
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
			rsaPublicKey = RSAUtil.getPublicKey(RSAUtil.decodeBase64(Key.PublicKey));
			 byte[] encryptData = RSAUtil.encrypt(rsaPublicKey,content.getBytes(Charset.forName("utf-8")));  
			  miTxt = RSAUtil.encodeBase64(encryptData);//密文
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}	
		return miTxt;
	}
}
