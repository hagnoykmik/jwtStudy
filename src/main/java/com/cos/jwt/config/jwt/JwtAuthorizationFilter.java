package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetail;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// 시큐리티가 filter 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때, 위 필터를 무조건 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  // 생성자
  public JwtAuthorizationFilter(
      AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 됨
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {
    System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

    String jwtHeader = request.getHeader(JwtProperties.HEADE_STRING);
    System.out.println("jwtHeader: " + jwtHeader);

    // header가 있는지 확인
    if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
      chain.doFilter(request, response);
      return;
    }

    // JWT토큰을 검증해서 정상적인 사용자인지 확인
    String jwtToken = request.getHeader(JwtProperties.HEADE_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
    System.out.println("jwtToken: " + jwtToken);

    String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
        .build().verify(jwtToken)    // 서명
        .getClaim("username")  // 서명이 정상적으로 되면 username을 가지고 온다
        .asString();

    // username이 정상적으로 들어왔으면 서명이 정상적으로 된것
    if (username != null) {
      System.out.println("username 정상");
      User userEntity = userRepository.findByUsername(username); // 확인

      System.out.println("userEntity: " + userEntity.getUsername());
      PrincipalDetail principalDetail = new PrincipalDetail(userEntity);

      // 강제로 만들어준다.
      // jwt 토큰 서명을 통해서 서명이 정상이라면 Authentication객체를 만들어 준다.
      Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail, null, principalDetail.getAuthorities());

      // 시큐리티를 저장할 수 있는 세션 공간을 찾은거임
      // 강제로 시큐리티의 세션에 접근하여 Authentication객체를 저장
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    chain.doFilter(request, response);

  }
}
