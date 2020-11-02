package com.friendship41.authserver.service

import com.friendship41.authserver.data.MemberAuthInfo
import com.friendship41.authserver.data.MemberAuthInfoRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.util.*
import java.util.stream.Collectors

@Component
class ReactiveUserDetailsServiceImpl(
        @Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository
): ReactiveUserDetailsService {

    override fun findByUsername(username: String): Mono<UserDetails> = Mono
            .justOrEmpty(
                    memberAuthInfoRepository.findByMemberId(username)
                            ?: memberAuthInfoRepository.findByMemberEmail(username))
            .filter(Objects::nonNull)
            .switchIfEmpty(Mono.error(BadCredentialsException("username=${username} not found")))
            .map(this::convertToSpringSecurityUser)

    private fun convertToSpringSecurityUser(memberAuthInfo: MemberAuthInfo): User = User(
            memberAuthInfo.memberNo.toString(),
            memberAuthInfo.memberPassword,
            memberAuthInfo.memberRole.split(",").stream()
                    .map { SimpleGrantedAuthority(it) }
                    .collect(Collectors.toList()))
}
