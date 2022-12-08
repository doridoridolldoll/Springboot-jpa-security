package dev.com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); //내 서버가 응답 할 때 json을 자바스클비트에서 처리 할 수 있게 할지 설정하는 것
        config.addAllowedOrigin("*"); //모든 ip 응답 허용
        config.addAllowedHeader("*"); //모든 header 응답 허용
        config.addAllowedMethod("*"); //모든 post, get, put, delete, patch 요청 허용
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}