package dev.com.security.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.com.security.model.Member;
import dev.com.security.security.auth.PrincipalDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        System.out.println("request = " + request);
        System.out.println("response = " + response);

        // 1.username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            Member member = om.readValue(request.getInputStream(), Member.class);
            System.out.println("member = " + member);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(member.getUsername(), (member.getPassword()));
            System.out.println("authenticationToken = " + authenticationToken);

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨

//            System.out.println("authentication = " + authentication);

            // authentication 객체가 session영역에 저장됨.
//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//            System.out.println("principalDetails = " + principalDetails.getMember().getUsername());
//            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 2.정상인지 로그인 시도
        // 3.PrincipalDetailsService 호출 -> loadUserByUsername() 함수 실행
        // 4.PrincipalDetails 를 세션에 담고 (권한 관리를 위해서)
        // 5.JWT 토큰 만들어서 응답
        return null;
    }

}
