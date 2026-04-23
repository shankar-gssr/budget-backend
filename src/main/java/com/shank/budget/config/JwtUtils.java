package com.shank.budget.config;

import com.shank.budget.login.LoginEntity;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.Function;

@Component
public class JwtUtils {

    @Value("${app.jwt.access.secret}")
    private String accessSecretBase64;

    @Value("${app.jwt.refresh.secret}")
    private String refreshSecretBase64;

    @Value("${app.jwt.access.expMs}")
    private long accessExpMs;

    @Value("${app.jwt.refresh.expMs}")
    private long refreshExpMs;

    @Autowired
    HttpServletRequest request;

    private SecretKey accessKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessSecretBase64));
    }

    private SecretKey refreshKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecretBase64));
    }

    public String generateAccessToken(LoginEntity user) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + accessExpMs);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userSerialNo", user.getUserId());
        claims.put("mobileNo", user.getMobile());

        String encryptedUserId = AESUtils.encrypt(String.valueOf(user.getUserId()));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(encryptedUserId)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(accessKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(LoginEntity user) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshExpMs);

        String encryptedUserId = AESUtils.encrypt(String.valueOf(user.getUserId()));

        return Jwts.builder()
                .setSubject(encryptedUserId)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(refreshKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public boolean validateAccessToken(String token) {
        parse(token, true);
        return true;
    }

    public boolean validateRefreshToken(String token) {
        parse(token, false);
        return true;
    }

    public String getStringExpirationDateFromToken(String token) {
        Date expDate = getClaimFromToken(token, Claims::getExpiration);
        SimpleDateFormat df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
        return df.format(expDate);
    }


    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(getKey()).parseClaimsJws(token).getBody();
    }

    public Key getKey() {
//		System.out.println("**** jwtSecret: " + jwtSecret);
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(accessSecretBase64);
//		System.out.println("**** apiKeySecretBytes: " + Arrays.toString(apiKeySecretBytes));
        return new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
    }

    public String extractUsernameFromAccess(String token) {
        return parse(token, true).getBody().getSubject();
    }

    public String extractUsernameFromRefresh(String token) {
        return parse(token, false).getBody().getSubject();
    }

    private Jws<Claims> parse(String token, boolean access) {
        try {
            JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(access ? accessKey() : refreshKey())
                    .build();
            return parser.parseClaimsJws(token);
        } catch (JwtException e) {
            throw new RuntimeException("Unexpected error occurred. Please try again later.");
        }
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(accessKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractTokenFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        return null;
    }

    public Long extractUserId(HttpServletRequest request) {
        String token = extractTokenFromHeader(request);
        Claims claims = extractAllClaims(token);
        return claims.get("userSerialNo", Long.class);
    }

    public boolean isTokenExpired(String jwt) {
        try {
            Date expiration = getExpirationDateFromToken(jwt);
            return expiration.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
}
