package com.ohgiraffers.tomatolab_imean.auth.service;


import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import com.ohgiraffers.tomatolab_imean.members.model.dto.LoginMembersDTO;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class AuthService implements UserDetailsService {

    private final MembersService membersService;

    @Autowired
    public AuthService(MembersService membersService) {
        this.membersService = membersService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username은 HTML 폼의 username 필드에서 전달되는 값으로, membersCode를 의미합니다
        LoginMembersDTO loginMembersDTO = membersService.findByMembersCode(username);

        if (Objects.isNull(loginMembersDTO)) {
            throw new UsernameNotFoundException("회원 정보가 존재하지 않습니다.");
        }
        
        // MembersStatus에 따른 추가 검증
        MembersStatus status = loginMembersDTO.getMembersStatus();
        
        // 상태 체크 - ACTIVE가 아닌 경우 로그인 차단
        if (!MembersStatus.ACTIVE.equals(status)) {
            if (MembersStatus.DORMANT.equals(status)) {
                throw new LockedException("휴면 계정입니다. 관리자에게 문의하세요.");
            } else if (MembersStatus.DELETED.equals(status)) {
                throw new LockedException("삭제된 계정입니다. 관리자에게 문의하세요.");
            } else {
                throw new LockedException("비활성화된 계정입니다. 관리자에게 문의하세요.");
            }
        }

        return new AuthDetails(loginMembersDTO);
    }
}