package com.ohgiraffers.tomatolab_imean.members.service;

import com.ohgiraffers.tomatolab_imean.members.model.dto.LoginMembersDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.MembersDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.SinupDTO;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.repository.MembersRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class MembersService {

    private MembersRepository membersRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public MembersService(MembersRepository membersRepository, PasswordEncoder passwordEncoder) {
        this.membersRepository = membersRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Long registerMembers(SinupDTO sinupDTO) {
        if (membersRepository.existsByMembersCode(sinupDTO.getMembersCode())) {
            return -1L;
        }
        else if (membersRepository.existsByMembersEmail(sinupDTO.getMembersEmail())) {
            return -2L;
        }
        else if (membersRepository.existsByMembersPhone(sinupDTO.getMembersPhone())) {
            return -3L;
        }

        try {
            Members members = new Members(
                    sinupDTO.getMembersCode(),
                    passwordEncoder.encode(sinupDTO.getMembersPassword()),
                    sinupDTO.getMembersNickName(), // 변경된 부분: 이름 필드가 NickName으로 되어 있음
                    sinupDTO.getMembersEmail(),
                    sinupDTO.getMembersPhone(),
                    sinupDTO.getMembersStatus()
            );

            Members savedMembers = membersRepository.save(members);
            return savedMembers.getMembersId();
        } catch (Exception e) {
            e.printStackTrace();
            return 0L;
        }
    }

    public MembersDTO findById(Long membersId) {
        Optional<Members> members = membersRepository.findById(membersId);

        return members.map(m -> new MembersDTO(
                m.getMembersId(),
                m.getMembersCode(),
                m.getMembersPass(),
                m.getMembersNickName(),
                m.getMembersEmail(),
                m.getMembersPhone(),
                m.getMembersRole(),
                m.getMembersStatus(),
                m.getCoupleCode(),
                m.getMembersUpdatedAt(),
                m.getMembersCreatedAt(),
                m.getMembersDeletedAt()
        )).orElse(null);
    }

    @Transactional
    public boolean updateProfile(Long membersId, MembersDTO membersDTO) {
        Members members = membersRepository.findById(membersId).orElse(null);
        if (members == null) {
            return false;
        }

        // 비밀번호가 제공된 경우 업데이트
        if (membersDTO.getMembersPass() != null && !membersDTO.getMembersPass().trim().isEmpty()) {
            members.setMembersPass(passwordEncoder.encode(membersDTO.getMembersPass()));
        }

        // 일반 필드 업데이트
        members.setMembersEmail(membersDTO.getMembersEmail());
        members.setMembersPhone(membersDTO.getMembersPhone());
        members.setMembersUpdatedAt(LocalDateTime.now());

        membersRepository.save(members);
        return true;
    }

    public Members findByCode(String code) throws ChangeSetPersister.NotFoundException {
        return membersRepository.findByMembersCode(code)
                .orElseThrow(() -> new ChangeSetPersister.NotFoundException());
    }

    public LoginMembersDTO findByMembersCode(String membersCode) {
        Optional<Members> members = membersRepository.findByMembersCode(membersCode);
        
        return members.map(m -> new LoginMembersDTO(
                m.getMembersId(),
                m.getMembersCode(),
                m.getMembersPass(),
                m.getMembersNickName(),
                m.getMembersEmail(),
                m.getMembersPhone(),
                m.getMembersRole(),
                m.getMembersStatus()
        )).orElse(null);
    }
}