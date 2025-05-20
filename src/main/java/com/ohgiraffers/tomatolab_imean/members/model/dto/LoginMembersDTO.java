package com.ohgiraffers.tomatolab_imean.members.model.dto;


import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;

public class LoginMembersDTO {

    private Long membersId;
    private String membersCode;
    private String membersPass;
    private String membersNickName;
    private String membersEmail;
    private String membersPhone;
    private MembersRole membersRole = MembersRole.MEMBERS;
    private MembersStatus membersStatus = MembersStatus.ACTIVE;

    public LoginMembersDTO(Long membersId, String membersCode, String membersPass, String membersNickName, String membersEmail, String membersPhone, MembersRole membersRole, MembersStatus membersStatus) {
        this.membersId = membersId;
        this.membersCode = membersCode;
        this.membersPass = membersPass;
        this.membersNickName = membersNickName;
        this.membersEmail = membersEmail;
        this.membersPhone = membersPhone;
        this.membersRole = membersRole;
        this.membersStatus = membersStatus;
    }

    public Long getMembersId() {
        return membersId;
    }

    public void setMemberId(Long membersId) {
        this.membersId = membersId;
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

    @Override
    public String toString() {
        return "LoginMembersDTO{" +
                "membersId=" + membersId +
                ", membersCode='" + membersCode + '\'' +
                ", membersPass='" + membersPass + '\'' +
                ", membersNickName='" + membersNickName + '\'' +
                ", membersEmail='" + membersEmail + '\'' +
                ", membersPhone='" + membersPhone + '\'' +
                ", membersRole=" + membersRole +
                ", membersStatus=" + membersStatus +
                '}';
    }
}