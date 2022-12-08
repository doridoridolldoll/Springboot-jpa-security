package dev.com.security.config;

import dev.com.security.security.auth.PrincipalDetailsService;
import dev.com.security.security.filter.MyFilter3;
import dev.com.security.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalDetailsService principalDetailsService;
    private final CorsFilter corsFilter;
    private final AuthenticationManager authenticationManager;

    /**
     * security Login
     * @param http
     * @return
     * @throws Exception
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> {
//                    auth.requestMatchers("/api/user/**").authenticated();
//                    auth.requestMatchers("/api/manager/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN");
//                    auth.requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN");
//                    auth.anyRequest().permitAll();
//                })
//                .userDetailsService(principalDetailsService)
//                .formLogin()
////                .headers(headers -> headers.frameOptions().sameOrigin())
//                .loginPage("/loginForm")
//                .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
//                .and()
//                .oauth2Login()
////                // 1.코드받기 (인증) 2.액세스토큰(권한) 3.사용자 프로필 정보 가져옴 4-1 가져온 정보로 자동 회원가입
////                // 4-2 (이메일,전화번호,이름,아이디) 쇼핑몰 -> (집주소),백화점몰 -> (vip등급,일반등급)
//                .loginPage("/loginForm")// 구글로그인의 완료 후 후처리 필요 -> (토큰+프로필 받음)
//                .userInfoEndpoint()
//                .and()
//                .and()
//                .build();
//    }

    /**
     * security jwt
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) //@CrossOrigin(인증X), 시큐리티 필터에 등록(인증O)
                .formLogin().disable()
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter()) // AuthenticationManager
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/user/**").authenticated();
                    auth.requestMatchers("/api/manager/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN");
                    auth.requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN");
                    auth.anyRequest().permitAll();
                })
                .build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
