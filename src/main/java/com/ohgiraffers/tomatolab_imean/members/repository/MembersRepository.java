package com.ohgiraffers.tomatolab_imean.members.repository;


import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MembersRepository extends CrudRepository<Members, Long> {

    Optional<Members> findByMembersId(Long membersId);
    boolean existsByMembersId(Long membersId);

    boolean existsByMembersCode(String membersCode);

    boolean existsByMembersEmail(String membersEmail);

    boolean existsByMembersPhone(String membersPhone);

    Optional<Members> findByMembersEmail(String email);

    Optional<Members> findByMembersCode(String code);
}