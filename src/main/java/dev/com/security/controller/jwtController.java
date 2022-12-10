package dev.com.security.controller;

import dev.com.security.dao.UserDao;
import dev.com.security.dto.AuthRequest;
import dev.com.security.model.Member;
import dev.com.security.security.auth.PrincipalDetailsService;
import dev.com.security.security.jwt.JwtUtils;
import dev.com.security.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class jwtController {

//    @Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private MemberService memberService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PrincipalDetailsService userDetailsService;
    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("join")
    public String join(@RequestBody Member member) {
        member.setRoles("ROLE_MANAGER");
//        Member entity = memberService.dtoToEntity(dto);
        memberService.saveMember(member);
        return "회원가입완료";
    }

    @GetMapping
    public String home() {
        return "Hello, JWT!";
    }

    @PostMapping("/auth")
    public ResponseEntity<String> authenticate(@RequestBody AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        if (userDetails != null) {
            return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
        }
        return ResponseEntity.status(400).body("Some error has occurred");
    }
}
