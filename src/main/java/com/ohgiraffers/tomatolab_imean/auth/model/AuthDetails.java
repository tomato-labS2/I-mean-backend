package com.ohgiraffers.tomatolab_imean.auth.model;

import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Spring Security에서 사용자 인증 정보를 담는 클래스
 */
public class AuthDetails implements UserDetails {

    private Long membersId;
    private String membersCode;
    private String membersPass;
    private MembersRole membersRole;
    private MembersStatus membersStatus;

    /**
     * 생성자
     */
    public AuthDetails(Long membersId, String membersCode, String membersPass, 
                       MembersRole membersRole, MembersStatus membersStatus) {
        this.membersId = membersId;
        this.membersCode = membersCode;
        this.membersPass = membersPass;
        this.membersRole = membersRole;
        this.membersStatus = membersStatus;
    }

    /**
     * 권한 정보 반환
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // 역할 기반 권한 추가 (ROLE_ 접두사 필요)
        authorities.add(new SimpleGrantedAuthority("ROLE_" + membersRole.name()));
        
        // 상태 기반 권한 추가
        authorities.add(new SimpleGrantedAuthority("STATUS_" + membersStatus.name()));
        
        // 커플 권한은 서비스 로직에서 별도 처리

        return authorities;
    }

    /**
     * 비밀번호 반환
     */
    @Override
    public String getPassword() {
        return membersPass;
    }

    /**
     * 사용자 식별자 반환 (Spring Security에서는 username 필드로 사용)
     */
    @Override
    public String getUsername() {
        return membersCode; // 로그인 식별자로 membersCode 사용
    }

    /**
     * 계정 만료 여부
     */
    @Override
    public boolean isAccountNonExpired() {
        return true; // 계정 만료 기능 사용하지 않음
    }

    /**
     * 계정 잠금 여부
     */
    @Override
    public boolean isAccountNonLocked() {
        return MembersStatus.ACTIVE.equals(membersStatus);
    }

    /**
     * 자격 증명(비밀번호) 만료 여부
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 비밀번호 만료 기능 사용하지 않음
    }

    /**
     * 계정 활성화 여부
     */
    @Override
    public boolean isEnabled() {
        return MembersStatus.ACTIVE.equals(membersStatus);
    }

    // Getter 메서드
    public Long getMembersId() {
        return membersId;
    }

    public String getMembersCode() {
        return membersCode;
    }
    
    public MembersRole getMembersRole() {
        return membersRole;
    }
    
    public MembersStatus getMembersStatus() {
        return membersStatus;
    }
}