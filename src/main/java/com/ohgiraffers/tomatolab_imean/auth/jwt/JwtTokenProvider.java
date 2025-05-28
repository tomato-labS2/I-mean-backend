package com.ohgiraffers.tomatolab_imean.auth.jwt;

import com.ohgiraffers.tomatolab_imean.auth.exception.InvalidTokenException;
import com.ohgiraffers.tomatolab_imean.auth.exception.TokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT 토큰 생성, 검증, 파싱을 담당하는 핵심 클래스
 */
@Component
public class JwtTokenProvider {
    
    // 로깅을 위한 Logger 수동 선언
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    
    private final JwtProperties jwtProperties;
    
    // 생성자
    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }
    
    /**
     * JWT 서명에 사용할 비밀키 생성
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Access Token 생성 (기존 버전 - 하위 호환)
     */
    public String createAccessToken(String memberCode) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtProperties.getAccessTokenExpiration());
        
        return Jwts.builder()
                .setSubject(memberCode)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }
    
    /**
     * Access Token 생성 (커플 상태 포함 버전)
     */
    public String createAccessToken(String memberCode, String coupleStatus, String memberRole) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtProperties.getAccessTokenExpiration());
        
        return Jwts.builder()
                .setSubject(memberCode)
                .claim("coupleStatus", coupleStatus)  // SINGLE or COUPLED
                .claim("memberRole", memberRole)      // MEMBER, GENERAL_ADMIN, SUPER_ADMIN
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }
    
    /**
     * Refresh Token 생성
     */
    public String createRefreshToken(String memberCode) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtProperties.getRefreshTokenExpiration());


        
        return Jwts.builder()
                .setSubject(memberCode)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }
    
    /**
     * 토큰에서 회원 코드 추출
     */
    public String getMemberCodeFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .parseClaimsJws(token)
                    .getBody();
            
            return claims.getSubject();
        } catch (ExpiredJwtException e) {
            logger.warn("만료된 토큰에서 정보 추출 시도: {}", e.getMessage());
            throw new TokenExpiredException("Access Token", true);
        } catch (Exception e) {
            logger.error("토큰에서 회원 코드 추출 실패: {}", e.getMessage());
            throw new InvalidTokenException("토큰에서 사용자 정보를 추출할 수 없습니다.", e);
        }
    }
    
    /**
     * 토큰에서 커플 상태 추출
     */
    public String getCoupleStatusFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .parseClaimsJws(token)
                    .getBody();
            
            return claims.get("coupleStatus", String.class);
        } catch (ExpiredJwtException e) {
            logger.warn("만료된 토큰에서 커플 상태 추출 시도: {}", e.getMessage());
            throw new TokenExpiredException("Access Token", true);
        } catch (Exception e) {
            logger.debug("토큰에서 커플 상태 추출 실패 (구버전 토큰일 수 있음): {}", e.getMessage());
            return "SINGLE"; // 기본값으로 SINGLE 반환
        }
    }
    
    /**
     * 토큰에서 회원 역할 추출
     */
    public String getMemberRoleFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .parseClaimsJws(token)
                    .getBody();
            
            return claims.get("memberRole", String.class);
        } catch (ExpiredJwtException e) {
            logger.warn("만료된 토큰에서 회원 역할 추출 시도: {}", e.getMessage());
            throw new TokenExpiredException("Access Token", true);
        } catch (Exception e) {
            logger.debug("토큰에서 회원 역할 추출 실패 (구버전 토큰일 수 있음): {}", e.getMessage());
            return "MEMBER"; // 기본값으로 MEMBER 반환
        }
    }
    
    /**
     * 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            logger.warn("만료된 토큰입니다: {}", e.getMessage());
            throw new TokenExpiredException("Access Token", true);
        } catch (UnsupportedJwtException e) {
            logger.warn("지원하지 않는 토큰입니다: {}", e.getMessage());
            throw InvalidTokenException.unsupportedToken();
        } catch (MalformedJwtException e) {
            logger.warn("잘못된 형식의 토큰입니다: {}", e.getMessage());
            throw InvalidTokenException.malformedToken();
        } catch (SignatureException e) {
            logger.warn("잘못된 서명의 토큰입니다: {}", e.getMessage());
            throw InvalidTokenException.invalidSignature();
        } catch (IllegalArgumentException e) {
            logger.warn("빈 토큰입니다: {}", e.getMessage());
            throw InvalidTokenException.emptyToken();
        }
    }
    
    /**
     * 토큰 만료 시간 확인
     */
    public Date getExpirationFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .parseClaimsJws(token)
                    .getBody();
            
            return claims.getExpiration();
        } catch (Exception e) {
            logger.error("토큰 만료 시간 확인 실패: {}", e.getMessage());
            throw new InvalidTokenException("토큰 만료 시간을 확인할 수 없습니다.", e);
        }
    }
    
    /**
     * 토큰이 곧 만료되는지 확인 (30분 이내)
     */
    public boolean isTokenExpiringSoon(String token) {
        try {
            Date expiration = getExpirationFromToken(token);
            Date now = new Date();
            long timeDiff = expiration.getTime() - now.getTime();
            return timeDiff < (30 * 60 * 1000); // 30분 이내면 true
        } catch (Exception e) {
            logger.warn("토큰 만료 시간 확인 중 오류: {}", e.getMessage());
            return true; // 오류가 발생하면 만료된 것으로 간주
        }
    }
    
    // Getter 메서드
    public JwtProperties getJwtProperties() {
        return jwtProperties;
    }
}