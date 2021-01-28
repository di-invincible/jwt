package com.example.jwt.exception;

/**
 * Created by macro on 2020/6/23.
 */
public class JwtInvalidException extends RuntimeException{
    public JwtInvalidException(String message) {
        super(message);
    }
}
