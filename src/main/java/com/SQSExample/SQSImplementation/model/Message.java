package com.SQSExample.SQSImplementation.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Message {

	// message id
	private final int id;
	// message text
	private final String message;

	@JsonCreator
	public Message(@JsonProperty("id") final int id, @JsonProperty("message") final String message) {
		this.id = id;
		this.message = message;
	}

	public int getId() {
		return id;
	}
	
	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return "Message [id=" + id + ", message=" + message + "]";
	}
	
}
