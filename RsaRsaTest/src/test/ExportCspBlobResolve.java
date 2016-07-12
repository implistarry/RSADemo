package test;

import java.util.Hashtable;

public class ExportCspBlobResolve {
	 /** 
     * 解析公钥 
     * @param cspblobPublicKey由C# new RSACryptoServiceProvider().ExportCspBlob(false)提供 
     * @return RSA公钥的Modulus参数 
     */  
    public static byte[] publicKeyResolve(byte[] cspblobPublicKey){  
        int length = cspblobPublicKey.length;  
        byte[] reversePublicKey = new byte[length];  
        for (int i = 0; i < length; i++) {  
            reversePublicKey[i] = cspblobPublicKey[length - 1 - i];  
        }         
        byte[] part = new byte[128];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePublicKey[i];  
        return part;          
    }  
      
    /** 
     * 解析私钥 
     * @param cspblobPrivateKey由C# new RSACryptoServiceProvider().ExportCspBlob(true)提供 
     * @return 返回包含私钥参数的Hashtable 
     */  
    public static Hashtable<String, byte[]> privateKeyResolve(byte[] cspblobPrivateKey) {  
        Hashtable<String, byte[]> privateKeyParameters = new Hashtable<String, byte[]>();  
        int length = cspblobPrivateKey.length;  
        byte[] reversePrivateKey = new byte[length];  
        for (int i = 0; i < length; i++) {  
            reversePrivateKey[i] = cspblobPrivateKey[length - 1 - i];  
        }  
        int offset = 0;  
        byte[] part = new byte[128];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("D", part);  
          
        offset += part.length;  
        part = new byte[64];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("INVERSEQ", part);  
          
        offset += part.length;  
        part = new byte[64];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("DQ", part);  
          
        offset += part.length;  
        part = new byte[64];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("DP", part);  
          
        offset += part.length;  
        part = new byte[64];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("Q", part);  
          
        offset += part.length;  
        part = new byte[64];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("P", part);  
          
        offset += part.length;  
        part = new byte[128];  
        for (int i = 0; i < part.length; i++)  
            part[i] = reversePrivateKey[offset + i];  
        privateKeyParameters.put("MODULUS", part);  
        return privateKeyParameters;  
    }     
}
