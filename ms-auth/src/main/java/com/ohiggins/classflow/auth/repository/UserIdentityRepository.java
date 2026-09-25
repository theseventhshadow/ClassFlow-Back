package com.ohiggins.classflow.auth.repository;

import com.ohiggins.classflow.auth.entity.UserIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserIdentityRepository extends JpaRepository<UserIdentity, Long> {

    Optional<UserIdentity> findByProviderAndTenantIdAndExternalSubject(
            String provider,
            String tenantId,
            String externalSubject);

    List<UserIdentity> findByUserId(Long userId);

    boolean existsByProviderAndTenantIdAndExternalSubject(
            String provider,
            String tenantId,
            String externalSubject);
}