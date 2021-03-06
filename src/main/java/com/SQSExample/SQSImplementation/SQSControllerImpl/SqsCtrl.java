
/*
package com.SQSExample.SQSImplementation.SQSControllerImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.aws.messaging.core.QueueMessagingTemplate;
import org.springframework.cloud.aws.messaging.listener.SqsMessageDeletionPolicy;
import org.springframework.cloud.aws.messaging.listener.annotation.SqsListener;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.SQSExample.SQSImplementation.model.Message;



//For creating the REST controllers.
@RestController
//Used to map incoming web requests onto the handler methods in the controller.
@RequestMapping(value = "/sqs")
public class SqsCtrl {

	 // Name of the queue. Developers are free to choose their queue name.
	 private static final String QUEUE = "ListenerExample";
	
	 public static final Logger LOGGER = LoggerFactory.getLogger(SqsCtrl.class);
	
	 // QueueMessagingTemplate initializes the messaging template by configuring the destination resolver as well as the message converter.
	 @Autowired
	 private QueueMessagingTemplate queueMessagingTemplate;
	 
	 @Autowired
	 private Consumer consumer;
	
	 // HTTP POST url - http://localhost:10091/sqs/send
	 @PostMapping(value = "/send")
	 // @ResponseStatus annotation marks the method with the status-code and the reason message that should be returned.
	 @ResponseStatus(code = HttpStatus.CREATED)
	 public void sendMessageToSqs(@RequestBody @Validated final Message message) {
	     LOGGER.info("Sending the message to the Amazon sqs.");
	     queueMessagingTemplate.convertAndSend(QUEUE, message);
	     LOGGER.info("Message sent successfully to the Amazon sqs.");
	 }
	
	 // @SqsListener listens to the message from the specified queue.
	 // Here in this example we are printing the message on the console and the message will be deleted from the queue once it is successfully delivered.
	 @SqsListener(value = QUEUE, deletionPolicy = SqsMessageDeletionPolicy.ON_SUCCESS)
	 public void getMessageFromSqs(@Validated Message message, @Header("MessageId") String messageId) {
		 LOGGER.info("Received message= {} with messageId= {}", message, messageId);
		 consumer.sendMessageToSqs(message);
		 // TODO - Developer can do some operations like saving the message to the database, calling any 3rd party etc.
	 }
}

*/
