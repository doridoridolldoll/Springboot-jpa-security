package dev.com.security.config;

import dev.com.security.security.PrincipalDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Autowired
    private PrincipalDetailsService principalDetailsService;
//    @Autowired
//    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/user/**").authenticated();
                    auth.requestMatchers("/manager/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN");
                    auth.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN");
                    auth.anyRequest().permitAll();
                })
                .userDetailsService(principalDetailsService)
                .formLogin()
//                .headers(headers -> headers.frameOptions().sameOrigin())
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
                .and()
                .oauth2Login()
//                // 1.코드받기 (인증) 2.액세스토큰(권한) 3.사용자 프로필 정보 가져옴 4-1 가져온 정보로 자동 회원가입
//                // 4-2 (이메일,전화번호,이름,아이디) 쇼핑몰 -> (집주소),백화점몰 -> (vip등급,일반등급)
                .loginPage("/loginForm")// 구글로그인의 완료 후 후처리 필요 -> (토큰+프로필 받음)
                .userInfoEndpoint()
//                .userService(principalOauth2UserService)
                .and()
                .and()
                .build();
    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
