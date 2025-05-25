package com.ohgiraffers.tomatolab_imean.couple.service;


import com.ohgiraffers.tomatolab_imean.couple.model.common.CoupleStatus;
import com.ohgiraffers.tomatolab_imean.couple.model.entity.Couple;
import com.ohgiraffers.tomatolab_imean.couple.repository.CoupleRepository;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class CoupleService {

    private final CoupleRepository coupleRepository;
    private final MembersService membersService;

    @Autowired
    public CoupleService(CoupleRepository coupleRepository, MembersService membersService) {
        this.coupleRepository = coupleRepository;
        this.membersService = membersService;
    }

    /**
     * 현재 멤버가 커플인지 확인
     */
    public boolean isAlreadyInCouple(Members member) {
        return coupleRepository.existsByMember1OrMember2(member, member);
    }

    /**
     * 커플 코드 생성
     */
    private String generateCoupleCode() {
        StringBuilder sb = new StringBuilder();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        
        for (int i = 0; i < 10; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }
        
        return sb.toString();
    }

    /**
     * 멤버 ID로 커플 정보 조회
     */
    public Optional<Couple> findCoupleByMember(Members member) {
        return coupleRepository.findByMember1OrMember2(member, member);
    }

    /**
     * 커플 등록 처리
     */
    @Transactional
    public Couple registerCouple(Members currentMember, String targetMemberCode) throws NotFoundException {
        // 대상 멤버 조회
        Members targetMember = membersService.findByCode(targetMemberCode);
        
        // 자기 자신인지 확인
        if (currentMember.getMembersId().equals(targetMember.getMembersId())) {
            throw new IllegalArgumentException("자신의 코드는 입력할 수 없습니다.");
        }
        
        // 이미 커플인지 확인
        if (isAlreadyInCouple(currentMember)) {
            throw new IllegalStateException("이미 커플 관계가 존재합니다.");
        }
        
        // 상대방이 이미 커플인지 확인
        if (isAlreadyInCouple(targetMember)) {
            throw new IllegalStateException("상대방이 이미 커플 관계에 있습니다.");
        }
        
        // 커플 코드 생성
        String coupleCode = generateCoupleCode();
        
        // 새 커플 생성
        Couple newCouple = new Couple();
        newCouple.setMember1(currentMember);
        newCouple.setMember2(targetMember);
        newCouple.setCoupleCode(coupleCode);
        newCouple.setCreatedAt(LocalDateTime.now());
        newCouple.setStatus(CoupleStatus.ACTIVE);
        
        // 회원 정보 업데이트
        currentMember.setCoupleCode(coupleCode);
        targetMember.setCoupleCode(coupleCode);
        
        // 저장
        return coupleRepository.save(newCouple);
    }

    /**
     * 커플의 파트너 찾기
     */
    public Members getPartner(Couple couple, Members currentMember) {
        if (couple.getMember1().getMembersId().equals(currentMember.getMembersId())) {
            return couple.getMember2();
        } else {
            return couple.getMember1();
        }
    }
}
