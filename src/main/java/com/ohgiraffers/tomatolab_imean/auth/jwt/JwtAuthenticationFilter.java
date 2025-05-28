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
    
    // 생성자
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, AuthService authService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authService = authService;
    }
    
    /**
     * 실제 필터 로직을 수행하는 메서드
     * 모든 HTTP 요청에 대해 JWT 토큰 검증 수행
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, 
            HttpServletResponse response, 
            FilterChain filterChain) throws ServletException, IOException {
        
        try {
            // 1. 요청에서 JWT 토큰 추출
            String jwt = extractTokenFromRequest(request);
            
            // 2. 토큰이 있고, 현재 인증 정보가 없는 경우에만 처리
            if (StringUtils.hasText(jwt) && SecurityContextHolder.getContext().getAuthentication() == null) {
                
                // 3. 토큰 유효성 검사
                if (jwtTokenProvider.validateToken(jwt)) {
                    
                    // 4. 토큰에서 사용자 정보 추출
                    String memberCode = jwtTokenProvider.getMemberCodeFromToken(jwt);
                    String coupleStatus = jwtTokenProvider.getCoupleStatusFromToken(jwt);
                    String memberRole = jwtTokenProvider.getMemberRoleFromToken(jwt);
                    
                    // 5. 사용자 정보로 UserDetails 조회 (DB에서 최신 정보 확인)
                    UserDetails userDetails = authService.loadUserByUsername(memberCode);
                    
                    // 6. JWT에서 추출한 정보로 AuthDetails 업데이트 (커플 상태 포함)
                    if (userDetails instanceof com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) {
                        com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails authDetails = 
                            (com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) userDetails;
                        
                        // 토큰의 커플 상태가 실제 DB 상태와 다를 수 있으므로 DB 기준으로 재검증
                        // (토큰 갱신 시점과 커플 등록 시점이 다를 수 있음)
                        userDetails = new com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails(
                            authDetails.getMemberId(),
                            authDetails.getMemberCode(),
                            authDetails.getPassword(),
                            authDetails.getMemberRole(),
                            authDetails.getMemberStatus(),
                            coupleStatus  // JWT에서 추출한 커플 상태 사용
                        );
                    }
                    
                    // 7. 인증 토큰 생성
                    UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, 
                                    null, 
                                    userDetails.getAuthorities()
                            );
                    
                    // 8. 요청 정보를 인증 토큰에 설정
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    
                    // 9. Spring Security Context에 인증 정보 설정
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                    logger.debug("JWT 인증 성공 - 사용자: {}, 커플상태: {}", memberCode, coupleStatus);
                }
            }
            
        } catch (TokenExpiredException e) {
            logger.warn("토큰 만료: {}", e.getMessage());
            // 토큰 만료 시 인증 정보 제거
            SecurityContextHolder.clearContext();
            
        } catch (InvalidTokenException e) {
            logger.warn("유효하지 않은 토큰: {}", e.getMessage());
            // 유효하지 않은 토큰 시 인증 정보 제거
            SecurityContextHolder.clearContext();
            
        } catch (Exception e) {
            logger.error("JWT 인증 중 오류 발생: {}", e.getMessage());
            // 기타 오류 시 인증 정보 제거
            SecurityContextHolder.clearContext();
        }
        
        // 9. 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }
    
    /**
     * HTTP 요청에서 JWT 토큰을 추출하는 메서드
     * Authorization 헤더에서 "Bearer " 접두사를 제거하고 토큰만 반환
     * 
     * @param request HTTP 요청
     * @return JWT 토큰 문자열 (없으면 null)
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        
        // "Bearer "로 시작하는지 확인
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            // "Bearer " 제거 후 토큰만 반환
            return bearerToken.substring(7);
        }
        
        return null;
    }
    
    /**
     * 특정 경로에 대해 필터를 적용하지 않을 수 있도록 하는 메서드
     * 현재는 모든 요청에 대해 필터 적용
     * 
     * @param request HTTP 요청
     * @return false면 필터 적용, true면 필터 건너뜀
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        
        // 로그인, 회원가입 등은 JWT 검증 제외
        return path.startsWith("/api/member/login") ||
               path.startsWith("/api/member/register") ||
               path.startsWith("/api/public/") ||
               path.equals("/") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/");
    }
}