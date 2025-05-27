package com.ohgiraffers.tomatolab_imean.auth.service;

import com.ohgiraffers.tomatolab_imean.auth.exception.RefreshTokenNotFoundException;
import com.ohgiraffers.tomatolab_imean.auth.jwt.JwtTokenProvider;
import com.ohgiraffers.tomatolab_imean.members.model.entity.RefreshToken;
import com.ohgiraffers.tomatolab_imean.members.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Refresh Token 관리 서비스
 * Refresh Token의 생성, 저장, 검증, 갱신, 삭제 등을 담당
 */
@Service
@Transactional
public class RefreshTokenService {
    
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);
    
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    
    // 사용자당 최대 유지할 Refresh Token 개수
    private static final int MAX_TOKENS_PER_USER = 5;
    
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtTokenProvider jwtTokenProvider) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }
    
    /**
     * 새로운 Refresh Token 생성 및 저장
     * @param memberCode 회원 코드
     * @return 생성된 JWT Refresh Token 문자열
     */
    public String createAndSaveRefreshToken(String memberCode) {
        try {
            logger.info("RefreshToken 생성 시작 - 회원: {}", memberCode);
            
            // 1. JWT Refresh Token 생성
            String jwtRefreshToken = jwtTokenProvider.createRefreshToken(memberCode);
            logger.info("JWT RefreshToken 생성 완료 - 회원: {}", memberCode);
            
            // 2. RefreshToken 엔티티 생성
            String tokenId = UUID.randomUUID().toString();
            long expirationMs = jwtTokenProvider.getJwtProperties().getRefreshTokenExpiration();
            logger.info("토큰 정보 - ID: {}, 만료시간(ms): {}", tokenId, expirationMs);
            
            RefreshToken refreshToken = new RefreshToken(
                tokenId, 
                memberCode, 
                jwtRefreshToken, 
                expirationMs
            );
            logger.info("RefreshToken 엔티티 생성 완료 - 회원: {}", memberCode);
            
            // 3. DB에 저장
            RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
            logger.info("RefreshToken DB 저장 완료 - 회원: {}, 저장된 토큰ID: {}", memberCode, savedToken.getTokenId());
            
            // 4. 해당 사용자의 오래된 토큰 정리 (비동기)
            try {
                cleanUpOldTokensForUser(memberCode);
            } catch (Exception cleanupEx) {
                logger.warn("토큰 정리 중 오류 (무시) - 회원: {}, 오류: {}", memberCode, cleanupEx.getMessage());
            }
            
            logger.info("Refresh Token 생성 및 저장 완료 - 회원: {}, 토큰ID: {}", memberCode, tokenId);
            
            return jwtRefreshToken;
            
        } catch (Exception e) {
            logger.error("Refresh Token 생성 중 오류 발생 - 회원: {}, 오류: {}", memberCode, e.getMessage(), e);
            throw new RuntimeException("Refresh Token 생성에 실패했습니다.", e);
        }
    }
    
    /**
     * Refresh Token으로 새로운 Access Token 발급
     * @param refreshTokenValue JWT Refresh Token 값
     * @return 새로운 Access Token
     * @throws RefreshTokenNotFoundException 유효하지 않은 Refresh Token인 경우
     */
    public String refreshAccessToken(String refreshTokenValue) {
        try {
            // 1. Refresh Token 검증 및 조회
            RefreshToken refreshToken = validateAndGetRefreshToken(refreshTokenValue);
            
            // 2. 새로운 Access Token 생성
            String newAccessToken = jwtTokenProvider.createAccessToken(refreshToken.getMemberCode());
            
            // 3. Refresh Token 사용 기록 업데이트
            refreshToken.markAsUsed();
            refreshTokenRepository.save(refreshToken);
            
            logger.info("Access Token 갱신 완료 - 회원: {}, 토큰ID: {}", 
                    refreshToken.getMemberCode(), refreshToken.getTokenId());
            
            return newAccessToken;
            
        } catch (RefreshTokenNotFoundException e) {
            logger.warn("유효하지 않은 Refresh Token으로 갱신 시도: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Access Token 갱신 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("토큰 갱신에 실패했습니다.", e);
        }
    }
    
    /**
     * Access Token과 Refresh Token 모두 갱신 (토큰 로테이션)
     * @param refreshTokenValue 기존 Refresh Token 값
     * @return 새로운 토큰 쌍 [accessToken, refreshToken]
     */
    public String[] rotateTokens(String refreshTokenValue) {
        try {
            // 1. 기존 Refresh Token 검증 및 조회
            RefreshToken oldRefreshToken = validateAndGetRefreshToken(refreshTokenValue);
            String memberCode = oldRefreshToken.getMemberCode();
            
            // 2. 기존 Refresh Token 폐기
            oldRefreshToken.revoke();
            refreshTokenRepository.save(oldRefreshToken);
            
            // 3. 새로운 토큰 쌍 생성
            String newAccessToken = jwtTokenProvider.createAccessToken(memberCode);
            String newRefreshToken = createAndSaveRefreshToken(memberCode);
            
            logger.info("토큰 로테이션 완료 - 회원: {}", memberCode);
            
            return new String[]{newAccessToken, newRefreshToken};
            
        } catch (Exception e) {
            logger.error("토큰 로테이션 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("토큰 로테이션에 실패했습니다.", e);
        }
    }
    
    /**
     * 회원의 모든 Refresh Token 폐기 (로그아웃 시 사용)
     * @param memberCode 회원 코드
     */
    public void revokeAllUserTokens(String memberCode) {
        try {
            int revokedCount = refreshTokenRepository.revokeAllTokensByMemberCode(memberCode);
            logger.info("회원의 모든 Refresh Token 폐기 완료 - 회원: {}, 폐기된 토큰 수: {}", memberCode, revokedCount);
        } catch (Exception e) {
            logger.error("Refresh Token 폐기 중 오류 발생 - 회원: {}, 오류: {}", memberCode, e.getMessage());
            throw new RuntimeException("토큰 폐기에 실패했습니다.", e);
        }
    }
    
    /**
     * 특정 Refresh Token 폐기
     * @param refreshTokenValue 폐기할 Refresh Token 값
     */
    public void revokeRefreshToken(String refreshTokenValue) {
        try {
            RefreshToken refreshToken = refreshTokenRepository.findByTokenValue(refreshTokenValue)
                    .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh Token을 찾을 수 없습니다."));
            
            refreshToken.revoke();
            refreshTokenRepository.save(refreshToken);
            
            logger.info("Refresh Token 폐기 완료 - 토큰ID: {}", refreshToken.getTokenId());
        } catch (Exception e) {
            logger.error("Refresh Token 폐기 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("토큰 폐기에 실패했습니다.", e);
        }
    }
    
    /**
     * 회원의 유효한 Refresh Token 목록 조회
     * @param memberCode 회원 코드
     * @return 유효한 RefreshToken 목록
     */
    @Transactional(readOnly = true)
    public List<RefreshToken> getValidTokensByMemberCode(String memberCode) {
        return refreshTokenRepository.findValidTokensByMemberCode(memberCode, LocalDateTime.now());
    }
    
    /**
     * Refresh Token 유효성 검증 및 조회
     * @param refreshTokenValue Refresh Token 값
     * @return 유효한 RefreshToken 엔티티
     * @throws RefreshTokenNotFoundException 유효하지 않은 경우
     */
    private RefreshToken validateAndGetRefreshToken(String refreshTokenValue) {
        // 1. JWT 자체 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshTokenValue)) {
            throw new RefreshTokenNotFoundException("유효하지 않은 Refresh Token입니다.");
        }
        
        // 2. DB에서 토큰 조회
        RefreshToken refreshToken = refreshTokenRepository.findValidTokenByValue(
                refreshTokenValue, LocalDateTime.now())
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh Token을 찾을 수 없거나 만료되었습니다."));
        
        // 3. 추가 유효성 검사
        if (!refreshToken.isValid()) {
            throw new RefreshTokenNotFoundException("Refresh Token이 폐기되었거나 만료되었습니다.");
        }
        
        return refreshToken;
    }
    
    /**
     * 사용자의 오래된 토큰 정리 (최신 N개만 유지) - MySQL LIMIT 문제 해결
     * 두 단계로 분리하여 MySQL의 LIMIT + SUBQUERY 제한을 우회합니다.
     * 
     * @param memberCode 회원 코드
     */
    private void cleanUpOldTokensForUser(String memberCode) {
        try {
            logger.debug("사용자 토큰 정리 시작 - 회원: {}, 최대 유지 개수: {}", memberCode, MAX_TOKENS_PER_USER);
            
            // 1단계: 유지할 최신 N개 토큰 ID 조회
            Pageable pageable = PageRequest.of(0, MAX_TOKENS_PER_USER);
            List<String> tokenIdsToKeep = refreshTokenRepository.findRecentTokenIdsByMemberCode(memberCode, pageable);
            
            logger.debug("유지할 토큰 ID 조회 완료 - 회원: {}, 유지할 토큰 수: {}", memberCode, tokenIdsToKeep.size());
            
            // 2단계: 유지할 토큰을 제외하고 나머지 삭제
            int deletedCount = 0;
            if (!tokenIdsToKeep.isEmpty()) {
                deletedCount = refreshTokenRepository.deleteTokensExcept(memberCode, tokenIdsToKeep);
            } else if (MAX_TOKENS_PER_USER == 0) {
                // keepCount가 0이면 모든 토큰 삭제
                deletedCount = refreshTokenRepository.deleteAllTokensByMemberCode(memberCode);
            }
            
            if (deletedCount > 0) {
                logger.info("사용자 오래된 토큰 정리 완료 - 회원: {}, 삭제된 토큰 수: {}, 유지된 토큰 수: {}", 
                           memberCode, deletedCount, tokenIdsToKeep.size());
            } else {
                logger.debug("삭제할 오래된 토큰 없음 - 회원: {}, 현재 토큰 수: {}", memberCode, tokenIdsToKeep.size());
            }
            
        } catch (Exception e) {
            logger.warn("사용자 토큰 정리 중 오류 발생 - 회원: {}, 오류: {}", memberCode, e.getMessage());
            // 토큰 정리 실패는 중요하지 않은 오류이므로 예외를 다시 던지지 않음
        }
    }
    
    /**
     * Refresh Token으로 새로운 Access Token 발급 (커플 상태 포함 버전)
     * @param refreshTokenValue JWT Refresh Token 값
     * @param memberCode 회원 코드
     * @param coupleStatus 변경된 커플 상태
     * @param memberRole 회원 역할
     * @return 새로운 Access Token (커플 상태 포함)
     */
    public String refreshAccessTokenWithCoupleStatus(String refreshTokenValue, String memberCode, 
                                                    String coupleStatus, String memberRole) {
        try {
            // 1. Refresh Token 검증
            RefreshToken refreshToken = validateAndGetRefreshToken(refreshTokenValue);
            
            // 2. 새로운 Access Token 생성 (커플 상태 포함)
            String newAccessToken = jwtTokenProvider.createAccessToken(memberCode, coupleStatus, memberRole);
            
            // 3. Refresh Token 사용 기록 업데이트
            refreshToken.markAsUsed();
            refreshTokenRepository.save(refreshToken);
            
            logger.info("Access Token 갱신 완료 (커플 상태 포함) - 회원: {}, 커플 상태: {}", memberCode, coupleStatus);
            
            return newAccessToken;
            
        } catch (Exception e) {
            logger.error("Access Token 갱신 중 오류 발생 (커플 상태 포함): {}", e.getMessage());
            throw new RuntimeException("토큰 갱신에 실패했습니다.", e);
        }
    }

    // ========== 스케줄링 메서드들 ==========
    
    /**
     * 만료된 Refresh Token 정리 (매일 새벽 2시 실행)
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        try {
            int deletedCount = refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
            logger.info("만료된 Refresh Token 정리 완료 - 삭제된 토큰 수: {}", deletedCount);
        } catch (Exception e) {
            logger.error("만료된 토큰 정리 중 오류 발생: {}", e.getMessage());
        }
    }
    
    /**
     * 폐기된 Refresh Token 정리 (매주 일요일 새벽 3시 실행)
     */
    @Scheduled(cron = "0 0 3 * * SUN")
    public void cleanupRevokedTokens() {
        try {
            int deletedCount = refreshTokenRepository.deleteRevokedTokens();
            logger.info("폐기된 Refresh Token 정리 완료 - 삭제된 토큰 수: {}", deletedCount);
        } catch (Exception e) {
            logger.error("폐기된 토큰 정리 중 오류 발생: {}", e.getMessage());
        }
    }
    
    // ========== 통계/모니터링 메서드들 ==========
    
    /**
     * 회원별 유효한 토큰 개수 조회
     */
    @Transactional(readOnly = true)
    public long countValidTokensByMember(String memberCode) {
        return refreshTokenRepository.countValidTokensByMemberCode(memberCode, LocalDateTime.now());
    }
    
    /**
     * 전체 유효한 토큰 개수 조회
     */
    @Transactional(readOnly = true)
    public long countAllValidTokens() {
        return refreshTokenRepository.countValidTokens(LocalDateTime.now());
    }
}