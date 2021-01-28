package com.example.jwt.controller;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.json.JSONUtil;
import com.example.jwt.entity.dto.PayloadDto;
import com.example.jwt.result.CommonResult;
import com.example.jwt.result.ErrorCode;
import com.example.jwt.service.JwtTokenService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

/**
 * 生成JWT令牌的接口
 * @author aaron
 * @since 2021-01-28
 */


@RestController
@RequestMapping("/token")
public class JwtTokenController {

    @Autowired
    private JwtTokenService jwtTokenService;

    /**
     * 使用对称加密（HMAC）算法生成token
     * @return
     */
    @GetMapping("/hmac/generate")
    public CommonResult<String> generateTokenByHMAC() {
        try {
            PayloadDto payloadDto = jwtTokenService.getDefaultPayloadDto();
            String token = jwtTokenService.generateTokenByHMAC(JSONUtil.toJsonStr(payloadDto), SecureUtil.md5("test"));
            return CommonResult.success(token);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return CommonResult.failed(ErrorCode.B0001);
    }

    /**
     * 使用对称加密（HMAC）算法验证token
     * @param token
     * @return
     */
    @GetMapping("/hmac/verify")
    public CommonResult<PayloadDto> verifyTokenByHMAC(String token) {
        try {
            PayloadDto payloadDto  = jwtTokenService.verifyTokenByHMAC(token, SecureUtil.md5("test"));
            return CommonResult.success(payloadDto);
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        }
        return CommonResult.failed(ErrorCode.B0001);
    }

    /**
     * 获取非对称加密（RSA）算法公钥
     */
    @GetMapping("/rsa/publicKey")
    public Object getRSAPublicKey() {
        RSAKey key = jwtTokenService.getDefaultRSAKey();
        return new JWKSet(key).toJSONObject();
    }


    /**
     * 使用非对称加密（RSA）算法生成token
     * @return
     */
    @GetMapping("/rsa/generate")
    public CommonResult<String> generateTokenByRSA() {
        try {
            PayloadDto payloadDto = jwtTokenService.getDefaultPayloadDto();
            String token = jwtTokenService.generateTokenByRSA(JSONUtil.toJsonStr(payloadDto),jwtTokenService.getDefaultRSAKey());
            return CommonResult.success(token);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return CommonResult.failed(ErrorCode.B0001);
    }

    /**
     * 使用非对称加密（RSA）算法验证token
     * @param token
     * @return
     */
    @GetMapping("/rsa/verify")
    public CommonResult<PayloadDto> verifyTokenByRSA(String token) {
        try {
            PayloadDto payloadDto  = jwtTokenService.verifyTokenByRSA(token, jwtTokenService.getDefaultRSAKey());
            return CommonResult.success(payloadDto);
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        }
        return CommonResult.failed(ErrorCode.B0001);
    }

}
