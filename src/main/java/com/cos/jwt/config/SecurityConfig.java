package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 시큐리티 활성화
@RequiredArgsConstructor
public class SecurityConfig {

  private final UserRepository userRepository;  // userRepository를 연결
  private final CorsConfig corsConfig;

  /*
    기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    => 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//    http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);  // 뒤의 필터(시큐리티 필터)가 걸리기 전에 내 필터를 건다. -> FilterConfig
    return http
        .csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 않겠다.
        .and()
        .formLogin().disable()    // formLogin안쓴다
        //////////////////////////// 위에 까지 고정 설정, 아래는 커스텀
        .httpBasic().disable()    // 기본적인 로그인 방식을 안쓴다 -> Bearer 방식 쓸거다
        .apply(new MyCustomDsl())
        .and()
        .authorizeRequests(authorize -> authorize.antMatchers("/api/v1/user/**")
            .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/manager/**")
            .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/admin/**")
            .access("hasRole('ROLE_ADMIN')")
            .anyRequest().permitAll())
        .build();
  }

  private class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {
      AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
      http
          .addFilter(corsConfig.corsFilter())
          // 서버는 cors 정책에서 벗어날 수 있다(모든 요청을 허용)
          // @CrossOrigin - 인증 x, 시큐리티 필터에 등록 - 인증 o
          .addFilter(new JwtAuthenticationFilter(authenticationManager))
          // /login을 쓰기위해 추가해준다 -> 파라미터로 AuthenticationManager을 던져줘야 한다.
          .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository)); // jwt 토큰이 유효한지 판단하는 필터
    }
  }
}
