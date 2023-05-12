package com.cos.jwt.controller;

import com.cos.jwt.config.auth.PrincipalDetail;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
public class RestApi {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping("home")
  public String home() {
    return "<h1>home</h1>";
  }

  @PostMapping("token")
  public String token() {
    return "<h1>token</h1>";
  }

  @PostMapping("join")
  public String join(@RequestBody User user) {
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    user.setRoles("ROLE_USER");  // 롤은 기본으로 설정해준다.
    userRepository.save(user);
    return "회원가입완료";
  }

  // user, manager, admin
  @GetMapping("/api/v1/user")
  public String user() {
    System.out.println("왜안돼");
    return "user";
  }

  // manager, admin
  @GetMapping("/api/v1/manager")
  public String manager() {
    return "manager";
  }

  // admin
  @GetMapping("/api/v1/admin")
  public String admin() {
    return "admin";
  }
}
