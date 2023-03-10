package com.vnpt.longan.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
@Slf4j
public class LoginController {

    @GetMapping("/login/success")
    @ResponseBody
    public ResponseEntity<Object> getLoginInfo(Authentication authentication) {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User user = token.getPrincipal();
        log.info(user.toString());
//        Map<String, Object> userInfo = new HashMap<>();
//        userInfo.put("id", user.getAttribute("sub"));
//        userInfo.put("username", user.getAttribute("name"));
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
    @GetMapping("/api/helo")
    public ResponseEntity<Object> getLoginInfxo() {
        return new ResponseEntity<>("Oke", HttpStatus.OK);
    }
}
