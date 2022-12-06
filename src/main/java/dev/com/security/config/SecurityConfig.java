package dev.com.security.config;

import dev.com.security.security.JpaUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Autowired
    JpaUserDetailsService jpaUserDetailsService;

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
                .userDetailsService(jpaUserDetailsService)
                .formLogin()
//                .headers(headers -> headers.frameOptions().sameOrigin())
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
                .and()
                .oauth2Login()
                .loginPage("/loginForm")// 구글로그인의 완료 후 후처리 필요 1.코드받기 (인증)
                .and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
