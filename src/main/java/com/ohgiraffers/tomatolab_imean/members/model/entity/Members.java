package com.ohgiraffers.tomatolab_imean.members.model.entity;

import com.ohgiraffers.tomatolab_imean.couple.model.entity.Couple;
import com.ohgiraffers.tomatolab_imean.members.model.common.MemberRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "members")
public class Members {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long memberId;

    @Column(name = "member_code", unique = true, nullable = false)
    private String memberCode;

    @Column(name = "member_pass", nullable = false)
    private String memberPass;

    @Column(name = "member_nickname", nullable = false)
    private String memberNickName;

    @Column(name = "member_email", nullable = false)
    private String memberEmail;

    @Column(name = "member_phone", nullable = false)
    private String memberPhone;

    @Enumerated(EnumType.STRING)
    @Column(name = "member_role", nullable = false)
    private MemberRole memberRole;

    @Enumerated(EnumType.STRING)
    @Column(name = "member_status", nullable = false)
    private MemberStatus memberStatus;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "couple_id", nullable = true)
    private Couple coupleId;

    @Column(name = "member_updatedat", nullable = true)
    private LocalDateTime memberUpdatedAt;

    @Column(name = "member_created_at", nullable = false)
    private LocalDateTime memberCreatedAt;

    @Column(name = "member_deletedat", nullable = true)
    private LocalDateTime memberDeletedAt;

    public Members() {
    }

    public Members(String membersCode, String memberPass) {
        this.memberCode = membersCode;
        this.memberPass = memberPass;
    }


    public Members(String membersCode, String memberPass, String memberNickName, String memberEmail, String memberPhone, MemberRole memberRole, MemberStatus memberStatus, Couple coupleId, LocalDateTime memberUpdatedAt, LocalDateTime memberCreatedAt, LocalDateTime membersDeletedA) {
        this.memberCode = membersCode;
        this.memberPass = memberPass;
        this.memberNickName = memberNickName;
        this.memberEmail = memberEmail;
        this.memberPhone = memberPhone;
        this.memberRole = memberRole;
        this.memberStatus = memberStatus;
        this.coupleId = coupleId;
        this.memberUpdatedAt = memberUpdatedAt;
        this.memberCreatedAt = memberCreatedAt;
        this.memberDeletedAt = memberDeletedAt;

    }

    public Members(String membersCode, String memberPass, String memberNickName, String memberEmail, String memberPhone, String memberStatus) {
        this.memberCode = membersCode;
        this.memberPass = memberPass;
        this.memberNickName = memberNickName;
        this.memberEmail = memberEmail;
        this.memberPhone = memberPhone;
        this.memberRole = MemberRole.MEMBER; // 기본값을 MEMBER로 설정
        this.memberStatus = com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus.valueOf("ACTIVE"); // 항상 ACTIVE로 설정
        this.memberCreatedAt = LocalDateTime.now(); // 생성 시간 설정
    }

    public Long getMemberId() {
        return memberId;
    }

    public String getMemberCode() {
        return memberCode;
    }

    public void setMemberCode(String membersCode) {
        this.memberCode = membersCode;
    }

    public String getMemberPass() {
        return memberPass;
    }

    public void setMemberPass(String membersPass) {
        this.memberPass = membersPass;
    }

    public String getMemberNickName() {
        return memberNickName;
    }

    public void setMemberNickName(String membersNickName) {
        this.memberNickName = membersNickName;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public void setMemberEmail(String membersEmail) {
        this.memberEmail = membersEmail;
    }

    public String getMemberPhone() {
        return memberPhone;
    }

    public void setMemberPhone(String membersPhone) {
        this.memberPhone = membersPhone;
    }

    public MemberRole getMemberRole() {
        return memberRole;
    }

    public void setMemberRole(MemberRole memberRole) {
        this.memberRole = memberRole;
    }

    public MemberStatus getMemberStatus() {
        return memberStatus;
    }

    public void setMemberStatus(MemberStatus memberStatus) {
        this.memberStatus = memberStatus;
    }

    public Couple getCoupleId() {
        return coupleId;
    }

    public void setCoupleId(Couple coupleCode) {
        this.coupleId = coupleCode;
    }

    public LocalDateTime getMemberUpdatedAt() {
        return memberUpdatedAt;
    }

    public void setMemberUpdatedAt(LocalDateTime membersUpdatedAt) {
        this.memberUpdatedAt = membersUpdatedAt;
    }

    public LocalDateTime getMemberCreatedAt() {
        return memberCreatedAt;
    }

    public void setMemberCreatedAt(LocalDateTime membersCreatedAt) {
        this.memberCreatedAt = membersCreatedAt;
    }

    public LocalDateTime getMemberDeletedAt() {
        return memberDeletedAt;
    }

    public void setMemberDeletedAt(LocalDateTime membersDeletedAt) {
        this.memberDeletedAt = membersDeletedAt;
    }



    // ========== 커플 상태 관련 메서드 ==========
    
    /**
     * 커플 관계에 있는지 확인
     * @return true if in couple relationship, false if single
     */
    public boolean isInCouple() {
        return this.coupleId != null && this.coupleId.getStatus() == com.ohgiraffers.tomatolab_imean.couple.model.common.CoupleStatus.ACTIVE;
    }
    
    /**
     * 싱글 상태인지 확인
     * @return true if single, false if in couple
     */
    public boolean isSingle() {
        return !isInCouple();
    }
    
    /**
     * 커플 상태를 문자열로 반환
     * @return "COUPLED" or "SINGLE"
     */
    public String getCoupleStatusString() {
        return isInCouple() ? "COUPLED" : "SINGLE";
    }

    @Override
    public String toString() {
        return "Members{" +
                "memberId=" + memberId +
                ", membersCode='" + memberCode + '\'' +
                ", membersPass='" + memberPass + '\'' +
                ", membersNickName='" + memberNickName + '\'' +
                ", membersEmail='" + memberEmail + '\'' +
                ", membersPhone='" + memberPhone + '\'' +
                ", membersRole=" + memberRole +
                ", membersStatus=" + memberStatus +
                ", coupleId='" + coupleId + '\'' +
                ", membersUpdatedAt=" + memberUpdatedAt +
                ", membersCreatedAt=" + memberCreatedAt +
                ", membersDeletedAt=" + memberDeletedAt;

    }
}