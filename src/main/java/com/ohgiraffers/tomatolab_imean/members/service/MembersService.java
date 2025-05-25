package com.ohgiraffers.tomatolab_imean.members.service;

import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import com.ohgiraffers.tomatolab_imean.members.model.dto.request.LoginRequestDTO;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.repository.MembersRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class MembersService {

    private final MembersRepository membersRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public MembersService(MembersRepository membersRepository, PasswordEncoder passwordEncoder) {
        this.membersRepository = membersRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    /**
     * API용 회원 가입 메서드
     */
    @Transactional
    public Members register(String membersCode, String membersPass, String membersNickName, 
                          String membersEmail, String membersPhone) {
        // 중복 검사
        if (membersRepository.existsByMembersCode(membersCode)) {
            throw new IllegalArgumentException("이미 사용 중인 회원 코드입니다.");
        }

        if (membersRepository.existsByMembersEmail(membersEmail)) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        if (membersRepository.existsByMembersPhone(membersPhone)) {
            throw new IllegalArgumentException("이미 사용 중인 전화번호입니다.");
        }

        // 회원 생성
        Members member = new Members();
        member.setMembersCode(membersCode);
        member.setMembersPass(passwordEncoder.encode(membersPass));
        member.setMembersNickName(membersNickName);
        member.setMembersEmail(membersEmail);
        member.setMembersPhone(membersPhone);
        member.setMembersRole(MembersRole.MEMBERS);
        member.setMembersStatus(MembersStatus.ACTIVE);
        member.setMembersCreatedAt(LocalDateTime.now());

        return membersRepository.save(member);
    }
    
    /**
     * API용 프로필 업데이트 메서드
     */
    @Transactional
    public Members updateMemberProfile(Long membersId, String newPassword, String email, String phone) {
        Members member = membersRepository.findById(membersId)
                .orElseThrow(() -> new IllegalArgumentException("회원을 찾을 수 없습니다."));
        
        // 비밀번호 업데이트 (제공된 경우)
        if (newPassword != null && !newPassword.trim().isEmpty()) {
            member.setMembersPass(passwordEncoder.encode(newPassword));
        }
        
        // 이메일 및 전화번호 업데이트
        if (email != null && !email.equals(member.getMembersEmail())) {
            // 이메일 중복 확인
            if (membersRepository.existsByMembersEmail(email) && 
                !member.getMembersEmail().equals(email)) {
                throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
            }
            member.setMembersEmail(email);
        }
        
        if (phone != null && !phone.equals(member.getMembersPhone())) {
            // 전화번호 중복 확인
            if (membersRepository.existsByMembersPhone(phone) && 
                !member.getMembersPhone().equals(phone)) {
                throw new IllegalArgumentException("이미 사용 중인 전화번호입니다.");
            }
            member.setMembersPhone(phone);
        }
        
        // 업데이트 시간 설정
        member.setMembersUpdatedAt(LocalDateTime.now());
        
        return membersRepository.save(member);
    }

    /**
     * ID로 회원 조회
     */
    public Members findById(Long id) {
        return membersRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("회원을 찾을 수 없습니다."));
    }

    /**
     * 회원 코드로 회원 검색
     */
    public Members findByCode(String code) throws ChangeSetPersister.NotFoundException {
        return membersRepository.findByMembersCode(code)
                .orElseThrow(() -> new ChangeSetPersister.NotFoundException());
    }
    
    /**
     * 이메일로 회원 검색
     */
    public Members findByEmail(String email) throws ChangeSetPersister.NotFoundException {
        return membersRepository.findByMembersEmail(email)
                .orElseThrow(() -> new ChangeSetPersister.NotFoundException());
    }
    
    /**
     * 이메일 또는 전화번호 중복 확인
     */
    public boolean isEmailAvailable(String email) {
        return !membersRepository.existsByMembersEmail(email);
    }
    
    public boolean isPhoneAvailable(String phone) {
        return !membersRepository.existsByMembersPhone(phone);
    }


    
    /**
     * 회원코드 중복 확인
     */
    public boolean isCodeAvailable(String code) {
        return !membersRepository.existsByMembersCode(code);
    }
}