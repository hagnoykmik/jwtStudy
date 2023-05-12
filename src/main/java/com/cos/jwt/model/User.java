package com.cos.jwt.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.Data;

@Data
@Entity
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;
  private String username;
  private String password;
  private String roles; // USER, ADMIN

  // role이 여러 개라서 처리
  public List<String> getRoleList() {
    if (this.roles.length() > 0) {
      return Arrays.asList(this.roles.split(","));
    }
    return new ArrayList<>(); // null안뜨게 처리
  }
}
