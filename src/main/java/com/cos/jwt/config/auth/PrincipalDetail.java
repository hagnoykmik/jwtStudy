package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import java.util.ArrayList;
import java.util.Collection;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
public class PrincipalDetail implements UserDetails {

  /**
   * UserDetails 인터페이스를 구현하여 사용자의 인증 정보를 담고 있는 객체를 만들고, 이를 Authentication 객체에 담아 인증을 처리합니다.
   */

  private User user;

  public PrincipalDetail(User user) {
    this.user = user;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Collection<GrantedAuthority> authorities = new ArrayList<>();
    user.getRoleList().forEach(r -> {
      authorities.add(() -> r);
    });

    return null;
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
