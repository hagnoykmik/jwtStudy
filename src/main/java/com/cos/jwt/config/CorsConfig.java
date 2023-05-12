package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * packageName    : com.cos.jwt.config fileName       : CosConfig author         : SSAFY date
 *    : 2023-05-11 description    : =========================================================== DATE
 *              AUTHOR             NOTE -----------------------------------------------------------
 * 2023-05-11        SSAFY       최초 생성
 */

@Configuration
public class CorsConfig {

  @Bean
  public CorsFilter corsFilter() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true); // 내 서버가 응답할때 json을 자바스크립트에서 처리할 수 있게 할지를 설정
    config.addAllowedOrigin("*");     // 모든 ip에 응답을 허용
    config.addAllowedHeader("*");     // 모든 header에 응답을 허용
    config.addAllowedMethod("*");     // 모든 post, get, put, delete, patch 요청을 허용
    source.registerCorsConfiguration("/api/**", config); // 이 주소는 config 설정을 따른다.

    return new CorsFilter(source);

  }
}
