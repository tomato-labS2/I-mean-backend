package com.ohgiraffers.tomatolab_imean.members.model.entity;

import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "members")
public class Members {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "members_id")
    private Long membersId;

    @Column(name = "members_code", unique = true, nullable = false)
    private String membersCode;

    @Column(name = "members_pass", nullable = false)
    private String membersPass;

    @Column(name = "members_nickname", nullable = false)
    private String membersNickName;

    @Column(name = "members_email", nullable = false)
    private String membersEmail;

    @Column(name = "members_phone", nullable = false)
    private String membersPhone;

    @Enumerated(EnumType.STRING)
    @Column(name = "members_role", nullable = false)
    private MembersRole membersRole = MembersRole.MEMBERS;

    @Enumerated(EnumType.STRING)
    @Column(name = "members_status", nullable = false)
    private MembersStatus membersStatus = MembersStatus.ACTIVE;

    @Column(name = "couple_code", nullable = true)
    private String coupleCode;

    @Column(name = "members_updatedat", nullable = true)
    private LocalDateTime membersUpdatedAt;

    @Column(name = "members_created_at", nullable = false)
    private LocalDateTime membersCreatedAt;

    @Column(name = "members_deletedat", nullable = true)
    private LocalDateTime membersDeletedAt;

    public Members() {
    }

    public Members(String membersCode, String membersPass) {
        this.membersCode = membersCode;
        this.membersPass = membersPass;
    }


    public Members(Long membersId, String membersCode, String membersPass, String membersNickName, String membersEmail, String membersPhone, MembersRole membersRole, MembersStatus membersStatus, String coupleCode, LocalDateTime membersUpdatedAt, LocalDateTime membersCreatedAt, LocalDateTime membersDeletedA) {
        this.membersId = membersId;
        this.membersCode = membersCode;
        this.membersPass = membersPass;
        this.membersNickName = membersNickName;
        this.membersEmail = membersEmail;
        this.membersPhone = membersPhone;
        this.membersRole = membersRole;
        this.membersStatus = membersStatus;
        this.coupleCode = coupleCode;
        this.membersUpdatedAt = membersUpdatedAt;
        this.membersCreatedAt = membersCreatedAt;
        this.membersDeletedAt = membersDeletedAt;

    }

    public Members(String membersCode, String membersPass, String membersNickName, String membersEmail, String membersPhone, String membersStatus) {
        this.membersCode = membersCode;
        this.membersPass = membersPass;
        this.membersNickName = membersNickName;
        this.membersEmail = membersEmail;
        this.membersPhone = membersPhone;
        this.membersRole = MembersRole.valueOf("USER"); // DEFAULT를 USER로 변경
        this.membersStatus = MembersStatus.valueOf("ACTIVE"); // 항상 ACTIVE로 설정
        this.membersCreatedAt = LocalDateTime.now(); // 생성 시간 설정
    }

    public Long getMembersId() {
        return membersId;
    }

    public void setMembersId(Long memberId) {
        this.membersId = memberId;
    }

    public String getMembersCode() {
        return membersCode;
    }

    public void setMembersCode(String membersCode) {
        this.membersCode = membersCode;
    }

    public String getMembersPass() {
        return membersPass;
    }

    public void setMembersPass(String membersPass) {
        this.membersPass = membersPass;
    }

    public String getMembersNickName() {
        return membersNickName;
    }

    public void setMembersNickName(String membersNickName) {
        this.membersNickName = membersNickName;
    }

    public String getMembersEmail() {
        return membersEmail;
    }

    public void setMembersEmail(String membersEmail) {
        this.membersEmail = membersEmail;
    }

    public String getMembersPhone() {
        return membersPhone;
    }

    public void setMembersPhone(String membersPhone) {
        this.membersPhone = membersPhone;
    }

    public MembersRole getMembersRole() {
        return membersRole;
    }

    public void setMembersRole(MembersRole membersRole) {
        this.membersRole = membersRole;
    }

    public MembersStatus getMembersStatus() {
        return membersStatus;
    }

    public void setMembersStatus(MembersStatus membersStatus) {
        this.membersStatus = membersStatus;
    }

    public String getCoupleCode() {
        return coupleCode;
    }

    public void setCoupleCode(String coupleCode) {
        this.coupleCode = coupleCode;
    }

    public LocalDateTime getMembersUpdatedAt() {
        return membersUpdatedAt;
    }

    public void setMembersUpdatedAt(LocalDateTime membersUpdatedAt) {
        this.membersUpdatedAt = membersUpdatedAt;
    }

    public LocalDateTime getMembersCreatedAt() {
        return membersCreatedAt;
    }

    public void setMembersCreatedAt(LocalDateTime membersCreatedAt) {
        this.membersCreatedAt = membersCreatedAt;
    }

    public LocalDateTime getMembersDeletedAt() {
        return membersDeletedAt;
    }

    public void setMembersDeletedAt(LocalDateTime membersDeletedAt) {
        this.membersDeletedAt = membersDeletedAt;
    }



    @Override
    public String toString() {
        return "Members{" +
                "memberId=" + membersId +
                ", membersCode='" + membersCode + '\'' +
                ", membersPass='" + membersPass + '\'' +
                ", membersNickName='" + membersNickName + '\'' +
                ", membersEmail='" + membersEmail + '\'' +
                ", membersPhone='" + membersPhone + '\'' +
                ", membersRole=" + membersRole +
                ", membersStatus=" + membersStatus +
                ", coupleCode='" + coupleCode + '\'' +
                ", membersUpdatedAt=" + membersUpdatedAt +
                ", membersCreatedAt=" + membersCreatedAt +
                ", membersDeletedAt=" + membersDeletedAt;

    }
}