package com.PKEClient.PKEClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SqsImplementationApplication {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SqsImplementationApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SqsImplementationApplication.class, args);
		LOGGER.info("Springboot with Amazon SQS service started successfully");
	}

}
