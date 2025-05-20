package com.ohgiraffers.tomatolab_imean.members.model.dto;


import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;

import java.time.LocalDateTime;

public class MembersDTO {
    private Long membersId;
    private String membersCode;
    private String membersPass;
    private String membersNickName;
    private String membersEmail;
    private String membersPhone;
    private MembersRole membersRole = MembersRole.MEMBERS;
    private MembersStatus membersStatus = MembersStatus.ACTIVE;
    private String coupleCode;
    private LocalDateTime membersUpdatedAt;
    private LocalDateTime membersCreatedAt;
    private LocalDateTime membersDeletedAt;

    public MembersDTO(Long membersId, String membersCode, String membersPass, String membersNickName, String membersEmail, String membersPhone, MembersRole membersRole, MembersStatus membersStatus, String coupleCode, LocalDateTime membersUpdatedAt, LocalDateTime membersCreatedAt, LocalDateTime membersDeletedAt) {
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
        return "MembersDTO{" +
                "membersId=" + membersId +
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
                ", membersDeletedAt=" + membersDeletedAt +
                '}';
    }
}