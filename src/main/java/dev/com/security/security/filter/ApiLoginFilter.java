//package dev.com.security.security.filter;
//
//import jakarta.servlet.ServletInputStream;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.log4j.Log4j2;
//import net.minidev.json.JSONObject;
//import org.apache.tomcat.util.json.JSONParser;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
//import org.springframework.util.StreamUtils;
//
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//
//@Log4j2
//public class ApiLoginFilter extends AbstractAuthenticationProcessingFilter {
//    private JWTUtil jwtUtil;
//
//    public ApiLoginFilter(String defaultFilterProcessUrl, JWTUtil jwtUtil) {
//        super(defaultFilterProcessUrl);
//        this.jwtUtil = jwtUtil;
//    }
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
//            throws AuthenticationException, IOException {
//        log.info("ApiLoginFilter........ attemptAuthentication");
//        log.info("request.getRequestURI():" + request.getRequestURI());
//
//        ServletInputStream inputStream = request.getInputStream();
//
//        String msgBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
//        log.info("msgBody:: " + msgBody);
//
//        JSONParser parser = new JSONParser();
//        JSONObject jsonObject = null;
//
//        try {
//            jsonObject = (JSONObject) parser.parse(msgBody);
//            log.info(jsonObject);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        String email = jsonObject.get("email").toString();
//        String pw = jsonObject.get("password").toString();
//        log.info("email: " + email + "/pw: " + pw);
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, pw);
//        return getAuthenticationManager().authenticate(authToken);
//    }
//
////    @Override
////    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
////                                            Authentication authResult) {
////        log.info("successfulAuthentication... authResult:" + authResult.getPrincipal());
////        String email = ((AuthMemberDTO) authResult.getPrincipal()).getEmail();
////        Long id = (((AuthMemberDTO) authResult.getPrincipal()).getId());
////        String token = null;
////        String curl = "";
////
////        ObjectMapper mapper = new ObjectMapper();
////        try {
////            token = "Bearer " + jwtUtil.generateToken(email, id);
////            TokenDTO tokenDTO = AuthToSessionDTO((AuthMemberDTO) authResult.getPrincipal(), token, curl);
////            String res = mapper.writeValueAsString(tokenDTO);
////            response.setContentType("application/json;charset=utf-8");
////            response.getOutputStream().write(res.getBytes());
////        } catch (Exception e) {
////            e.printStackTrace();
////        }
////    }
////
////    private TokenDTO AuthToSessionDTO(AuthMemberDTO dto,
////                                      String token, String curl) {
////        TokenDTO tokenDTO = TokenDTO.builder()
////                .id(dto.getId())
////                .email(dto.getEmail())
////                .name(dto.getName())
////                .token(token)
////                .fromSocial(dto.isFromSocial())
////                .curl(curl)
////                .build();
////        return tokenDTO;
////    }
//
//}
