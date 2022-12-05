package dev.com.security.config;

import dev.com.security.security.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    JpaUserDetailsService jpaUserDetailsService;

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        UserDetails manager = User.withDefaultPasswordEncoder()
                .username("manager")
                .password("password")
                .roles("MANAGER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
//                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/").permitAll();
                    auth.requestMatchers("/user/**").authenticated();
                    auth.requestMatchers("/manager/**").hasRole("('ADMIN') or ('MANAGER')");
                    auth.requestMatchers("/admin/**").hasRole("ADMIN");
                    auth.anyRequest().permitAll();
                })
                .userDetailsService(jpaUserDetailsService)
//                .headers(headers -> headers.frameOptions().sameOrigin())
                .formLogin()
                .loginPage("/members/login")
                .loginProcessingUrl("/members/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
                .defaultSuccessUrl("/admin")
                .and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
