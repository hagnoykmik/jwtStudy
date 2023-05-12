package com.cos.jwt.repository;

import com.cos.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * packageName    : com.cos.jwt.repository fileName       : UserRepository author         : SSAFY
 * date           : 2023-05-11 description    : ===========================================================
 * DATE              AUTHOR             NOTE -----------------------------------------------------------
 * 2023-05-11        SSAFY       최초 생성
 */
public interface UserRepository extends JpaRepository<User, Long> {
  User findByUsername(String username);
}
