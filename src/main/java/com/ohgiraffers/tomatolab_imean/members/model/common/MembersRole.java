package com.ohgiraffers.tomatolab_imean.members.model.common;

public enum MembersRole {
    MEMBERS("회원"),
    GENERAL_ADMIN("매니저"),
    SUPER_ADMIN("관리자");

    private final String description;

    MembersRole(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
