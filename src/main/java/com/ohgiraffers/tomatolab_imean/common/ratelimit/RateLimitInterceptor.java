package com.ohgiraffers.tomatolab_imean.common.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate Limiting 인터셉터
 * @RateLimit 어노테이션이 적용된 메서드의 요청 횟수를 제한합니다.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {
    
    private static final Logger logger = LoggerFactory.getLogger(RateLimitInterceptor.class);
    
    // 인메모리 캐시 (Caffeine 사용)
    private final Cache<String, AtomicInteger> requestCounts;
    private final ObjectMapper objectMapper;
    
    public RateLimitInterceptor(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        
        // Caffeine Cache 설정
        this.requestCounts = Caffeine.newBuilder()
                .maximumSize(10000)  // 최대 10,000개 키 저장
                .expireAfterWrite(Duration.ofHours(1))  // 1시간 후 자동 삭제
                .build();
                
        logger.info("RateLimitInterceptor 초기화 완료 - 인메모리 캐시 사용");
    }
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        
        // Handler가 메서드인지 확인
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        
        // @RateLimit 어노테이션 확인
        RateLimit rateLimit = handlerMethod.getMethodAnnotation(RateLimit.class);
        if (rateLimit == null) {
            return true; // Rate Limit이 없으면 통과
        }
        
        // Rate Limit 비활성화된 경우 통과
        if (!rateLimit.enabled()) {
            logger.debug("Rate Limit이 비활성화되어 있습니다.");
            return true;
        }
        
        try {
            // Rate Limit 키 생성
            String key = generateKey(request, rateLimit.keyType());
            
            // 시간 윈도우 파싱
            Duration windowDuration = parseWindow(rateLimit.window());
            
            // 현재 요청 횟수 확인 및 증가
            AtomicInteger count = requestCounts.get(key, k -> new AtomicInteger(0));
            int currentCount = count.incrementAndGet();
            
            logger.debug("Rate Limit 체크 - 키: {}, 현재 요청 수: {}/{}, 윈도우: {}", 
                        key, currentCount, rateLimit.requests(), rateLimit.window());
            
            // 제한 초과 확인
            if (currentCount > rateLimit.requests()) {
                handleRateLimitExceeded(response, rateLimit, key, currentCount);
                return false; // 요청 차단
            }
            
            // 첫 번째 요청인 경우 TTL 설정
            if (currentCount == 1) {
                // 새로운 윈도우 시작 - 캐시에 TTL 적용됨
                logger.debug("새로운 Rate Limit 윈도우 시작 - 키: {}, 윈도우: {}", key, windowDuration);
            }
            
            return true; // 요청 허용
            
        } catch (Exception e) {
            logger.error("Rate Limit 처리 중 오류 발생: {}", e.getMessage(), e);
            // 오류 발생 시 요청 허용 (fail-open 정책)
            return true;
        }
    }
    
    /**
     * Rate Limit 키 생성
     */
    private String generateKey(HttpServletRequest request, RateLimitKeyType keyType) {
        String baseKey = request.getRequestURI();
        
        switch (keyType) {
            case IP:
                return String.format("rate_limit:%s:%s", baseKey, getClientIpAddress(request));
                
            case USER:
                String userCode = getCurrentUserCode();
                if (userCode != null) {
                    return String.format("rate_limit:%s:user:%s", baseKey, userCode);
                } else {
                    // 로그인하지 않은 경우 IP로 대체
                    return String.format("rate_limit:%s:ip:%s", baseKey, getClientIpAddress(request));
                }
                
            case IP_AND_USER:
                String user = getCurrentUserCode();
                String ip = getClientIpAddress(request);
                return String.format("rate_limit:%s:%s:%s", baseKey, ip, user != null ? user : "anonymous");
                
            case GLOBAL:
                return String.format("rate_limit:%s:global", baseKey);
                
            default:
                return String.format("rate_limit:%s:%s", baseKey, getClientIpAddress(request));
        }
    }
    
    /**
     * 클라이언트 IP 주소 추출
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        
        // 여러 IP가 있는 경우 첫 번째 IP 사용
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }
        
        return ipAddress != null ? ipAddress : "unknown";
    }
    
    /**
     * 현재 로그인한 사용자 코드 추출
     */
    private String getCurrentUserCode() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated() && 
                !authentication.getPrincipal().equals("anonymousUser")) {
                
                // AuthDetails에서 사용자 코드 추출
                Object principal = authentication.getPrincipal();
                if (principal instanceof com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) {
                    com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails authDetails = 
                        (com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails) principal;
                    return authDetails.getMemberCode();
                }
            }
        } catch (Exception e) {
            logger.debug("사용자 코드 추출 실패: {}", e.getMessage());
        }
        return null;
    }
    
    /**
     * 시간 윈도우 문자열 파싱 ("1m", "30s", "1h" 등)
     */
    private Duration parseWindow(String window) {
        if (window == null || window.trim().isEmpty()) {
            return Duration.ofMinutes(1); // 기본값: 1분
        }
        
        window = window.trim().toLowerCase();
        
        if (window.endsWith("s")) {
            int seconds = Integer.parseInt(window.substring(0, window.length() - 1));
            return Duration.ofSeconds(seconds);
        } else if (window.endsWith("m")) {
            int minutes = Integer.parseInt(window.substring(0, window.length() - 1));
            return Duration.ofMinutes(minutes);
        } else if (window.endsWith("h")) {
            int hours = Integer.parseInt(window.substring(0, window.length() - 1));
            return Duration.ofHours(hours);
        } else if (window.endsWith("d")) {
            int days = Integer.parseInt(window.substring(0, window.length() - 1));
            return Duration.ofDays(days);
        } else {
            // 숫자만 있는 경우 분으로 간주
            try {
                int minutes = Integer.parseInt(window);
                return Duration.ofMinutes(minutes);
            } catch (NumberFormatException e) {
                logger.warn("잘못된 윈도우 형식: {}. 기본값(1분) 사용", window);
                return Duration.ofMinutes(1);
            }
        }
    }
    
    /**
     * Rate Limit 초과 시 처리
     */
    private void handleRateLimitExceeded(HttpServletResponse response, RateLimit rateLimit, 
                                        String key, int currentCount) throws Exception {
        
        logger.warn("🚨 Rate Limit 초과 - 키: {}, 요청 수: {}/{}, 메시지: {}", 
                   key, currentCount, rateLimit.requests(), rateLimit.message());
        
        // HTTP 상태코드 설정
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json;charset=UTF-8");
        
        // 오류 응답 생성
        ApiResponseDTO<Object> errorResponse = ApiResponseDTO.error(rateLimit.message());
        
        // JSON 응답 작성
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
}
