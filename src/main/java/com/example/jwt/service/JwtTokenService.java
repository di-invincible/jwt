package com.example.jwt.service;

import com.example.jwt.entity.dto.PayloadDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;


import java.text.ParseException;

/**
 * @author aaron
 * @since 2021-01-28
 */
public interface JwtTokenService {

    /**
     * 生成对称加密（HMAC) JWT令牌
     * @param payloadStr
     * @param secret
     * @return
     */
    String generateTokenByHMAC(String payloadStr, String secret) throws JOSEException;

    /**
     * 验证（HMAC) JWT令牌
     * @param token
     * @param secret
     * @return
     */
    PayloadDto verifyTokenByHMAC(String token, String secret) throws ParseException, JOSEException;

    PayloadDto getDefaultPayloadDto();

    RSAKey getDefaultRSAKey();

    String generateTokenByRSA(String payloadStr, RSAKey rsaKey) throws JOSEException;

    PayloadDto verifyTokenByRSA(String token, RSAKey rsaKey) throws ParseException, JOSEException;
}
