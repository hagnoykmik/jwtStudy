package com.cos.jwt.config.jwt;


public interface JwtProperties {
  String SECRET = "김경아";   // 우리 서버만 알고 있는 비밀값
  int EXPIRATION_TIME = 864000000;
  String TOKEN_PREFIX = "Bearer ";
  String HEADE_STRING = "Authorization";

}
