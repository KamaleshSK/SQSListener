package com.PKEClient.PKEClient.Models;

public class EncryptedResponseEntity {

	private String RSAEncryptedPublicKey;
	
	private String AESEncryptedData;

	public String getRSAEncryptedPublicKey() {
		return RSAEncryptedPublicKey;
	}

	public void setRSAEncryptedPublicKey(String rSAEncryptedPublicKey) {
		RSAEncryptedPublicKey = rSAEncryptedPublicKey;
	}

	public String getAESEncryptedData() {
		return AESEncryptedData;
	}

	public void setAESEncryptedData(String aESEncryptedData) {
		AESEncryptedData = aESEncryptedData;
	}
	
}
