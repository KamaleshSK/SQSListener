package com.PKEClient.PKEClient.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.PKEClient.PKEClient.Services.EncryptedService;

@RestController
@RequestMapping(value = "/secureaccess")
public class ClientController {
	
	@Autowired
	private EncryptedService encryptedService;
	
	@GetMapping(value = "/customerdata")
	public String getSecureData() {
		encryptedService.getDecryptedMessage();
		return "OK";
	}
	
}
