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

import java.util.HashMap;
import java.util.Map;

/**
 * JWT 인증 관련 컨트롤러 (member_id 포함 개선 버전)
 * 토큰 갱신, 인증 상태 확인, 로그아웃 등
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final com.ohgiraffers.tomatolab_imean.members.service.MemberService memberService;
    
    public AuthController(JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService,
                         com.ohgiraffers.tomatolab_imean.members.service.MemberService memberService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.memberService = memberService;
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
     * 🆕 Refresh Token으로 새로운 Access Token 발급 (member_id 포함)
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<TokenResponseDTO>> refreshToken(@RequestBody RefreshTokenRequestDTO request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("Refresh Token이 필요합니다."));
            }
            
            // 🔄 토큰에서 member_id와 memberCode 모두 추출
            Long memberId = jwtTokenProvider.getMemberIdFromToken(refreshToken);
            String memberCode = jwtTokenProvider.getMemberCodeFromToken(refreshToken);
            
            // 회원 정보 조회
            try {
                com.ohgiraffers.tomatolab_imean.members.model.entity.Members member;
                
                // member_id가 있으면 ID로 조회, 없으면 Code로 조회 (하위 호환성)
                if (memberId != null) {
                    member = memberService.findById(memberId);
                } else {
                    member = memberService.findByCode(memberCode);
                }
                
                // 🆕 새로운 Access Token 생성 (member_id 포함)
                String newAccessToken = jwtTokenProvider.createAccessToken(
                    member.getMemberId(),        // 🆕 member_id 포함
                    member.getMemberCode(),
                    member.getCoupleStatusString(),
                    member.getMemberRole().name()
                );
                
                long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
                
                TokenResponseDTO tokenResponse = new TokenResponseDTO(newAccessToken, expiresIn);
                
                return ResponseEntity.ok(ApiResponseDTO.success("토큰 갱신 성공", tokenResponse));
                
            } catch (org.springframework.data.crossstore.ChangeSetPersister.NotFoundException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("사용자 정보를 찾을 수 없습니다"));
            }
            
        } catch (RefreshTokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("토큰 갱신 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
    
    /**
     * 🆕 Access Token과 Refresh Token 모두 갱신 (토큰 로테이션)
     */
    @PostMapping("/refresh-rotate")
    public ResponseEntity<ApiResponseDTO<TokenResponseDTO>> refreshWithRotation(@RequestBody RefreshTokenRequestDTO request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("Refresh Token이 필요합니다."));
            }
            
            // 🔄 토큰에서 사용자 정보 추출
            Long memberId = jwtTokenProvider.getMemberIdFromToken(refreshToken);
            String memberCode = jwtTokenProvider.getMemberCodeFromToken(refreshToken);
            
            try {
                com.ohgiraffers.tomatolab_imean.members.model.entity.Members member;
                
                // member_id가 있으면 ID로 조회, 없으면 Code로 조회
                if (memberId != null) {
                    member = memberService.findById(memberId);
                } else {
                    member = memberService.findByCode(memberCode);
                }
                
                // 기존 Refresh Token 폐기
                refreshTokenService.revokeRefreshToken(refreshToken);
                
                // 🆕 새로운 토큰들 생성 (member_id 포함)
                String newAccessToken = jwtTokenProvider.createAccessToken(
                    member.getMemberId(),
                    member.getMemberCode(),
                    member.getCoupleStatusString(),
                    member.getMemberRole().name()
                );
                
                String newRefreshToken = jwtTokenProvider.createRefreshToken(
                    member.getMemberId(),
                    member.getMemberCode()
                );
                
                // 새 Refresh Token 저장
                refreshTokenService.saveRefreshToken(member.getMemberCode(), newRefreshToken);
                
                long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
                
                TokenResponseDTO tokenResponse = new TokenResponseDTO(newAccessToken, newRefreshToken, expiresIn);
                
                return ResponseEntity.ok(ApiResponseDTO.success("토큰 로테이션 성공", tokenResponse));
                
            } catch (org.springframework.data.crossstore.ChangeSetPersister.NotFoundException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("사용자 정보를 찾을 수 없습니다"));
            }
            
        } catch (RefreshTokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("토큰 로테이션 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
    
    /**
     * 🆕 현재 인증 상태 및 사용자 정보 확인
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponseDTO<Object>> getCurrentUser(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            
            // 🆕 JWT에서 member_id 정보도 포함하여 응답
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("memberId", authDetails.getMemberId());
            userInfo.put("memberCode", authDetails.getMemberCode());
            userInfo.put("memberRole", authDetails.getMemberRole().name());
            userInfo.put("coupleStatus", authDetails.getCoupleStatus());
            userInfo.put("isInCouple", authDetails.isInCouple());
            userInfo.put("isAdmin", authDetails.isAdmin());
            userInfo.put("isSuperAdmin", authDetails.isSuperAdmin());
            
            return ResponseEntity.ok(ApiResponseDTO.success("인증된 사용자 정보", userInfo));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error("인증이 필요합니다."));
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