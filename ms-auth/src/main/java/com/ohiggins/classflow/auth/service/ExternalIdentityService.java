package com.ohiggins.classflow.auth.service;

import com.ohiggins.classflow.auth.entity.User;
import com.ohiggins.classflow.auth.entity.UserIdentity;
import com.ohiggins.classflow.auth.exception.DuplicateResourceException;
import com.ohiggins.classflow.auth.repository.UserIdentityRepository;
import com.ohiggins.classflow.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Gestiona la vinculacion entre usuarios internos e identidades externas.
 */
@Service
@RequiredArgsConstructor
public class ExternalIdentityService {

    private final UserIdentityRepository userIdentityRepository;
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public Optional<UserIdentity> findIdentity(
            String provider,
            String tenantId,
            String externalSubject) {
        validateIdentityData(provider, tenantId, externalSubject);
        return userIdentityRepository.findByProviderAndTenantIdAndExternalSubject(
                normalizeProvider(provider), tenantId, externalSubject);
    }

    @Transactional
    public UserIdentity linkIdentity(
            Long userId,
            String provider,
            String tenantId,
            String externalSubject) {
        validateIdentityData(provider, tenantId, externalSubject);
        String normalizedProvider = normalizeProvider(provider);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        Optional<UserIdentity> existingIdentity = userIdentityRepository
                .findByProviderAndTenantIdAndExternalSubject(normalizedProvider, tenantId, externalSubject);
        if (existingIdentity.isPresent() && !existingIdentity.get().getUserId().equals(user.getId())) {
            throw new DuplicateResourceException("La identidad externa ya esta vinculada a otro usuario.");
        }
        if (existingIdentity.isPresent()) {
            return existingIdentity.get();
        }

        Optional<UserIdentity> currentProviderIdentity = userIdentityRepository
                .findByUserIdAndProviderAndTenantId(userId, normalizedProvider, tenantId);
        if (currentProviderIdentity.isPresent()) {
            throw new DuplicateResourceException("El usuario ya tiene una identidad vinculada para este proveedor.");
        }

        UserIdentity identity = new UserIdentity();
        identity.setUserId(user.getId());
        identity.setProvider(normalizedProvider);
        identity.setTenantId(tenantId);
        identity.setExternalSubject(externalSubject);
        return userIdentityRepository.save(identity);
    }

    private void validateIdentityData(String provider, String tenantId, String externalSubject) {
        if (provider == null || provider.isBlank()
                || tenantId == null || tenantId.isBlank()
                || externalSubject == null || externalSubject.isBlank()) {
            throw new IllegalArgumentException("Provider, tenantId y externalSubject son obligatorios.");
        }
    }

    private String normalizeProvider(String provider) {
        return provider.trim().toUpperCase();
    }
}