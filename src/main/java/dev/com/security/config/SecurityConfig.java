package dev.com.security.config;

import dev.com.security.dao.UserDao;
import dev.com.security.security.auth.PrincipalDetailsService;
import dev.com.security.security.jwt.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final JwtAuthFilter jwtAuthFilter;
    private final PrincipalDetailsService userDao;


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
//                .addFilterBefore(new JwtAuthenticationFilter(authenticationManager(principalDetailsService)), UsernamePasswordAuthenticationFilter.class)
//                .userDetailsService(principalDetailsService)
//                .formLogin()
////                .headers(headers -> headers.frameOptions().sameOrigin())
//                .loginPage("/loginForm")
//                .loginProcessingUrl("/login") // login ????????? ???????????? ??????????????? ???????????? ?????? ????????? ??????
//                .and()
//                .oauth2Login()
////                // 1.???????????? (??????) 2.???????????????(??????) 3.????????? ????????? ?????? ????????? 4-1 ????????? ????????? ?????? ????????????
////                // 4-2 (?????????,????????????,??????,?????????) ????????? -> (?????????),???????????? -> (vip??????,????????????)
//                .loginPage("/loginForm")// ?????????????????? ?????? ??? ????????? ?????? -> (??????+????????? ??????)
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
//                .userDetailsService(userDetailsService())
//                .addFilter(corsFilter) //@CrossOrigin(??????X), ???????????? ????????? ??????(??????O)
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .and().authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/user/**").authenticated();
                    auth.requestMatchers("/api/manager/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN");
                    auth.requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN");
                    auth.anyRequest().permitAll();
                })
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return userDao.loadUserByUsername(username);
            }
        };
    }
}