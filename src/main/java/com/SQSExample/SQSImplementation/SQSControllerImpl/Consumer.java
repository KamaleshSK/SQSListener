package com.SQSExample.SQSImplementation.SQSControllerImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.aws.messaging.core.QueueMessagingTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.SQSExample.SQSImplementation.model.Message;

@Component
public class Consumer {
	
	private static final String QUEUE = "ListenerExampleConsumer";
	
	public static final Logger LOGGER = LoggerFactory.getLogger(SqsCtrl.class);
	
	// QueueMessagingTemplate initializes the messaging template by configuring the destination resolver as well as the message converter.
	@Autowired
	private QueueMessagingTemplate queueMessagingTemplate;
	
	@ResponseStatus(code = HttpStatus.CREATED)
	public void sendMessageToSqs(@RequestBody @Validated final Message message) {
	    LOGGER.info("Sending the message to the Amazon sqs consumer queue");
	    queueMessagingTemplate.convertAndSend(QUEUE, message);
	    LOGGER.info("Message sent successfully to the Amazon sqs consumer queue");
	}
}
