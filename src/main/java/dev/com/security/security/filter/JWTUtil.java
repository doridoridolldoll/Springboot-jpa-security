//package dev.com.security.security.filter;
//
//
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.impl.DefaultClaims;
//import io.jsonwebtoken.impl.DefaultJws;
//import lombok.extern.log4j.Log4j2;
//
//import java.nio.charset.StandardCharsets;
//import java.time.ZonedDateTime;
//import java.util.Date;
//
//@Log4j2
//public class JWTUtil {
//    private final String secretKey = "overclock121212";
//    private final long expire = 60 * 24 * 30;
//
//    public String generateToken(String email, Long id) throws Exception {
//        String result = Jwts.builder()
//                .setIssuedAt(new Date())
//                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expire).toInstant()))
//                .claim("sub", email)
//                .claim("jti", id)
//                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes(StandardCharsets.UTF_8))
//                .compact();
//        log.info(result);
//        return result;
//    }
//
//    public String validateAndExtract(String tokenStr) {
//        log.info("================");
//        String checker = null;
//        try {
//            DefaultJws defaultjJws = (DefaultJws) Jwts.parser()
//                    .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(tokenStr);
//
//            DefaultClaims claims = (DefaultClaims) defaultjJws.getBody();
//            checker = claims.getSubject();
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            log.error(e.getMessage());
//            checker = null;
//        }
//        return checker;
//    }
//
//}
