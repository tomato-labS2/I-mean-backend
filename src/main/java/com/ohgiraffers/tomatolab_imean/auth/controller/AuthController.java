package com.ohgiraffers.tomatolab_imean.auth.controller;

import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/check")
    public ResponseEntity<ApiResponseDTO<?>> checkAuthStatus() {
        return ResponseEntity.ok(new ApiResponseDTO<>(true, "인증되었습니다.", null));
    }
}
