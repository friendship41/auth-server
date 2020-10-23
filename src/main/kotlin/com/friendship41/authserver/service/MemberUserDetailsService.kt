package com.friendship41.authserver.service

import com.friendship41.authserver.data.MemberAuthInfo
import com.friendship41.authserver.data.MemberAuthInfoRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class DefaultMemberUserDetailService(
        @Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository): UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        var memberAuthInfo: MemberAuthInfo? = memberAuthInfoRepository.findByMemberId(username)
        if (memberAuthInfo == null) memberAuthInfo = memberAuthInfoRepository.findByMemberEmail(username)

        if (memberAuthInfo == null)
            throw UsernameNotFoundException("No Such User")

        return User(
                username,
                memberAuthInfo.memberPassword,
                listOf<GrantedAuthority>(
                        SimpleGrantedAuthority(memberAuthInfo.memberRole)))
    }
}
