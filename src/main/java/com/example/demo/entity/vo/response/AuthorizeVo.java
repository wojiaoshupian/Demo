package com.example.demo.entity.vo.response;

import lombok.Data;

import java.util.Date;

@Data
public class AuthorizeVo {
    String username;
    String role;
    String token;
    Date expire;
}
