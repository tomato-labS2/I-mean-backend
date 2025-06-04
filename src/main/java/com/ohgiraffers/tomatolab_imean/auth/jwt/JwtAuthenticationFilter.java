package com.ohgiraffers.tomatolab_imean.auth.jwt;

import com.ohgiraffers.tomatolab_imean.auth.exception.InvalidTokenException;
import com.ohgiraffers.tomatolab_imean.auth.exception.TokenExpiredException;
import com.ohgiraffers.tomatolab_imean.auth.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT 인증 필터
 * 모든 HTTP 요청에서 JWT 토큰을 검사하고 인증 처리를 담당
 * OncePerRequestFilter를 상속하여 요청당 한 번만 실행됨
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;
    
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, AuthService authService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authService = authService;
    }
    
    /**
     * 실제 필터 로직을 수행하는 메서드
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, 
            HttpServletResponse response, 
            FilterChain filterChain) throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        logger.debug("🔍 JWT 필터 시작 - {} {}", method, requestURI);
        
        try {
            // 1. 요청에서 JWT 토큰 추출
            String jwt = extractTokenFromRequest(request);
            logger.debug("📋 추출된 JWT 토큰: {}", jwt != null ? "토큰 존재 (길이: " + jwt.length() + ")" : "토큰 없음");
            
            // 2. 토큰이 있고, 현재 인증 정보가 없는 경우에만 처리
            if (StringUtils.hasText(jwt) && SecurityContextHolder.getContext().getAuthentication() == null) {
                logger.debug("🔐 JWT 토큰 검증 시작...");
                
                // 3. 토큰 유효성 검사
                if (jwtTokenProvider.validateToken(jwt)) {
                    logger.debug("✅ JWT 토큰 유효성 검증 성공");
                    
                    // 4. 토큰에서 사용자 정보 추출
                    JwtTokenProvider.TokenUserInfo userInfo = jwtTokenProvider.getUserInfoFromToken(jwt);
                    logger.debug("👤 토큰에서 추출된 사용자 정보: {}", userInfo);
                    
                    // 5. 사용자 정보로 UserDetails 조회
                    UserDetails userDetails;
                    try {
                        logger.debug("🔍 사용자 정보 조회 시작 - memberId: {}, memberCode: {}", 
                                userInfo.getMemberId(), userInfo.getMemberCode());
                        userDetails = authService.loadUserByIdOrCode(userInfo.getMemberId(), userInfo.getMemberCode());
                        logger.debug("✅ 사용자 정보 조회 성공: {}", userDetails.getUsername());
                    } catch (Exception e) {
                        logger.warn("❌ 사용자 정보 조회 실패 - memberId: {}, memberCode: {}, 오류: {}", 
                                userInfo.getMemberId(), userInfo.getMemberCode(), e.getMessage());
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                    }
                    
                    // 6. JWT에서 추출한 정보로 AuthDetails 생성
                    if (userDetails instanceof com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) {
                        com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails originalAuthDetails = 
                            (com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) userDetails;
                        
                        userDetails = new com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails(
                            userInfo.getMemberId() != null ? userInfo.getMemberId() : originalAuthDetails.getMemberId(),
                            userInfo.getMemberCode(),
                            originalAuthDetails.getPassword(),
                            originalAuthDetails.getMemberRole(),
                            originalAuthDetails.getMemberStatus(),
                            userInfo.getCoupleStatus() != null ? userInfo.getCoupleStatus() : originalAuthDetails.getCoupleStatus(),
                            userInfo.getCoupleId() != null ? userInfo.getCoupleId() : originalAuthDetails.getCoupleId()
                        );
                        logger.debug("🔄 AuthDetails 업데이트 완료");
                    }
                    
                    // 7. 인증 토큰 생성 및 SecurityContext 설정
                    UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, 
                                    null, 
                                    userDetails.getAuthorities()
                            );
                    
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                    logger.debug("🎉 JWT 인증 성공 - ID: {}, Code: {}, Authorities: {}", 
                            userInfo.getMemberId(), userInfo.getMemberCode(), userDetails.getAuthorities());
                } else {
                    logger.warn("❌ JWT 토큰 유효성 검증 실패");
                }
            } else {
                logger.debug("⏭️ JWT 토큰 처리 건너뛰기 - 토큰: {}, 기존 인증: {}", 
                        StringUtils.hasText(jwt) ? "존재" : "없음", 
                        SecurityContextHolder.getContext().getAuthentication() != null ? "존재" : "없음");
            }
            
        } catch (TokenExpiredException e) {
            logger.warn("⏰ 토큰 만료: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            response.setHeader("X-Token-Expired", "true");
            
        } catch (InvalidTokenException e) {
            logger.warn("🚫 유효하지 않은 토큰: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            response.setHeader("X-Token-Invalid", "true");
            
        } catch (Exception e) {
            logger.error("💥 JWT 인증 중 오류 발생: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }
        
        // 8. 다음 필터로 요청 전달
        logger.debug("➡️ 다음 필터로 요청 전달");
        filterChain.doFilter(request, response);
    }
    
    /**
     * HTTP 요청에서 JWT 토큰을 추출하는 메서드
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        
        return null;
    }
    
    /**
     * 특정 경로에 대해 필터를 적용하지 않을 수 있도록 하는 메서드
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        String method = request.getMethod();
        
        // 공개 API 경로들 (인증이 불필요한 경로만)
        return path.startsWith("/api/member/login") ||
               path.startsWith("/api/member/register") ||
               path.startsWith("/api/member/check-email") ||
               path.startsWith("/api/auth/refresh") ||
               path.startsWith("/api/public/") ||
               (path.equals("/") || path.equals("/index.html")) ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.startsWith("/fonts/") ||
               path.startsWith("/webjars/") ||
               path.equals("/favicon.ico") ||
               "OPTIONS".equals(method); // CORS preflight 요청 제외
    }
}