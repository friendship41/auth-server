package com.friendship41.authserver.handler

import com.friendship41.authserver.data.MemberAuthInfo
import com.friendship41.authserver.data.MemberAuthInfoRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.ok
import org.springframework.web.reactive.function.server.body
import reactor.core.publisher.Mono

@Component
class MemberAuthHandler(@Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository,
                        @Autowired private val passwordEncoder: PasswordEncoder) {
    fun handlePostAuthinfo(request: ServerRequest): Mono<ServerResponse> = ok().body(
            request.bodyToMono(MemberAuthInfo::class.java)
                    .map {
                        it.memberPassword = passwordEncoder.encode(it.memberPassword)
                        memberAuthInfoRepository.save(it) }
                    .doOnNext { it.memberPassword="" })}
