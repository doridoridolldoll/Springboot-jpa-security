package dev.com.security.controller;

import dev.com.security.dto.MemberDto;
import dev.com.security.model.Member;
import dev.com.security.security.oauth.provider.LoginRequest;
import dev.com.security.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class jwtController {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
//    @Autowired
//    private AuthenticationManager authenticationManager;
    @Autowired
    private MemberService memberService;
//    @Autowired
//    private TokenService tokenService;

    @PostMapping("join")
    public String join(@RequestBody MemberDto dto) {
        dto.setRoles("ROLE_USER");
        Member entity = memberService.dtoToEntity(dto);
        memberService.saveMember(entity);
        return "회원가입완료";
    }

    @GetMapping
    public String home() {
        return "Hello, JWT!";
    }

//    @PostMapping("token")
//    public String token(@RequestBody LoginRequest userLogin) {
//        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLogin.username(), userLogin.password()));
//        return tokenService.generateToken(authentication);
//    }

}
