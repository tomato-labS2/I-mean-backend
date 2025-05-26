package com.ohgiraffers.tomatolab_imean.auth.controller;

import com.ohgiraffers.tomatolab_imean.auth.exception.RefreshTokenNotFoundException;
import com.ohgiraffers.tomatolab_imean.auth.jwt.JwtTokenProvider;
import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.auth.model.dto.request.RefreshTokenRequestDTO;
import com.ohgiraffers.tomatolab_imean.auth.model.dto.response.TokenResponseDTO;
import com.ohgiraffers.tomatolab_imean.auth.service.RefreshTokenService;
import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * JWT 인증 관련 컨트롤러
 * 토큰 갱신, 인증 상태 확인, 로그아웃 등
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    
    public AuthController(JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
    }
    
    /**
     * 현재 인증 상태 확인
     * JWT 토큰이 유효한지 확인
     */
    @GetMapping("/check")
    public ResponseEntity<ApiResponseDTO<Object>> checkAuthStatus(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok(ApiResponseDTO.success("인증되었습니다.", null));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error("인증이 필요합니다."));
        }
    }
    
    /**
     * Refresh Token으로 새로운 Access Token 발급
     * Access Token 만료 시 사용
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<TokenResponseDTO>> refreshToken(@RequestBody RefreshTokenRequestDTO request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            // Refresh Token 유효성 검사
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("Refresh Token이 필요합니다."));
            }
            
            // RefreshTokenService를 통한 토큰 갱신
            String newAccessToken = refreshTokenService.refreshAccessToken(refreshToken);
            long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
            
            // 응답 생성
            TokenResponseDTO tokenResponse = new TokenResponseDTO(newAccessToken, expiresIn);
            
            return ResponseEntity.ok(ApiResponseDTO.success("토큰 갱신 성공", tokenResponse));
            
        } catch (RefreshTokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("토큰 갱신 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
    
    /**
     * Access Token과 Refresh Token 모두 갱신 (토큰 로테이션)
     * 보안성을 높이기 위해 Refresh Token도 함께 갱신
     */
    @PostMapping("/refresh-rotate")
    public ResponseEntity<ApiResponseDTO<TokenResponseDTO>> refreshWithRotation(@RequestBody RefreshTokenRequestDTO request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            // Refresh Token 유효성 검사
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("Refresh Token이 필요합니다."));
            }
            
            // 토큰 로테이션 수행
            String[] newTokens = refreshTokenService.rotateTokens(refreshToken);
            String newAccessToken = newTokens[0];
            String newRefreshToken = newTokens[1];
            
            long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
            
            // 응답 생성 (새로운 Refresh Token 포함)
            TokenResponseDTO tokenResponse = new TokenResponseDTO(newAccessToken, newRefreshToken, expiresIn);
            
            return ResponseEntity.ok(ApiResponseDTO.success("토큰 로테이션 성공", tokenResponse));
            
        } catch (RefreshTokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("토큰 로테이션 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
    
    /**
     * 로그아웃 (모든 Refresh Token 폐기)
     * 사용자의 모든 디바이스에서 로그아웃 처리
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO<Object>> logout(Authentication authentication) {
        try {
            if (authentication != null && authentication.isAuthenticated()) {
                // 현재 인증된 사용자의 모든 Refresh Token 폐기
                AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
                String memberCode = authDetails.getMemberCode();
                
                refreshTokenService.revokeAllUserTokens(memberCode);
                
                return ResponseEntity.ok(ApiResponseDTO.success(
                    "로그아웃되었습니다. 모든 디바이스에서 로그아웃 처리되었습니다.", 
                    null
                ));
            } else {
                return ResponseEntity.ok(ApiResponseDTO.success(
                    "로그아웃되었습니다. 클라이언트에서 토큰을 삭제해주세요.", 
                    null
                ));
            }
        } catch (Exception e) {
            // 로그아웃은 실패하더라도 클라이언트에서 토큰 삭제하도록 안내
            return ResponseEntity.ok(ApiResponseDTO.success(
                "로그아웃되었습니다. 클라이언트에서 토큰을 삭제해주세요.", 
                null
            ));
        }
    }
    
    /**
     * 특정 Refresh Token만 폐기 (개별 디바이스 로그아웃)
     */
    @PostMapping("/logout-device")
    public ResponseEntity<ApiResponseDTO<Object>> logoutDevice(@RequestBody RefreshTokenRequestDTO request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("Refresh Token이 필요합니다."));
            }
            
            // 특정 Refresh Token만 폐기
            refreshTokenService.revokeRefreshToken(refreshToken);
            
            return ResponseEntity.ok(ApiResponseDTO.success(
                "해당 디바이스에서 로그아웃되었습니다.", 
                null
            ));
            
        } catch (RefreshTokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("로그아웃 처리 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
}