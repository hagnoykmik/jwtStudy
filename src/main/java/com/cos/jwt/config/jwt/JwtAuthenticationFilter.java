package com.cos.jwt.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetail;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login으로 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함
// .formLogin().disable()로 해놔서 동작안한다.
// 해결방법 -> 이 필터를 다시 SecurityConfig에 등록해준다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {

    System.out.println("JwtAuthenticationFilter: 로그인 시도중");

    // 1. request.getInputStream()에 담긴 username, password 받아서
    try {
      // 1-1. 기본적인 방법
//      BufferedReader br = request.getReader();
//
//      String input = null;
//      while ((input = br.readLine()) != null) {
//        System.out.println(input);  // JSON 파일 그대로 출력됨
//      }

      // 1-2. JSON파일 파싱하는 방법
      ObjectMapper om = new ObjectMapper();
      User user = om.readValue(request.getInputStream(), User.class);
      System.out.println(user);       // User(id=0, username=ssar, password=1234, roles=null)

      // token을 만들어준다.
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

      // 이 토큰으로 로그인 시도
      // token을 날린다 -> PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨 -> username만 받아주고 password는 스프링에서 알아서 처리해줌 -> 정상이면 authentication이 return됨
      // db에 있는 username과 password가 일치한다.
      Authentication authentication = authenticationManager.authenticate(authenticationToken);
      // authentication에 authenticationToken을 넣어서 던지면 인증을 한다 -> 인증 되면 authentication을 받는다 -> 내 로그인한 정보가 담긴다


      PrincipalDetail principalDetail = (PrincipalDetail) authentication.getPrincipal(); // Object를 반환 -> 메서드가 반환하는 객체를 PrincipalDetail 타입으로 캐스팅
      System.out.println("로그인 성공" + principalDetail.getUser().getUsername());  // => 로그인이 되었다는 뜻

      // authentication이 session영역에 저장해야하고 그 방법이 return 해주면 됨
      // return의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 함
      // 굳이 jwt 토큰을 사용하면서 세션을 만들어줄 이유가 없음. 근데 단지 권한 처리 때문에 session에 넣어준다.
      return authentication;
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행
  // jwt 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    System.out.println("successfulAuthentication이 실행됨 : 인증 완료");

    PrincipalDetail principalDetail = (PrincipalDetail) authResult.getPrincipal();

    // 토큰 생성
    String jwtToken = JWT.create()
        .withSubject("토큰이름")
        .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))      // 1000->1초 , 10분정도가 적당함
        .withClaim("id", principalDetail.getUser().getId())             // 비공개 claim
        .withClaim("username", principalDetail.getUser().getUsername())
        .sign(Algorithm.HMAC512(JwtProperties.SECRET));                       // 시크릿 키를 들고 있어야 함

    // 사용자에게 응답할 response header에
    response.addHeader(JwtProperties.HEADE_STRING, "Bearer " + jwtToken);
  }
}

// 기본적인 로그인 로직
/**
 * 1. 유저 네임 , 패스워드 로그인 정상
 * 2. 서버 쪽 세션ID 생성
 * 3. 클라이언트 쿠키로 세션 ID를 응답
 * 4. 그 다음부터 요청할 때마다 쿠키값 세션 ID를 항상 들고 서버쪽으로 요청하기 때문에
 * session.getAttribute("세션값 확인")
 * 서버는 세션 ID가 유효한지 판단(자동)해서 유효하면 인증이 필요한 페이지로 접근
  */

// 우리
/**
 * 1. 유저 네임 , 패스워드 로그인 정상
 * 2. JWT 토큰을 생성
 * 3. 클라이언트 쪽으로 JWT토큰을 응답
 * 4. 요청할 때마다 JWT 토큰을 가지고 요청
 * 5. 서버는 JWT토큰이 유효한지를 판단해야한다(필터 필요)
 */


