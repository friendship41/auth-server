package com.friendship41.authserver.handler

import com.friendship41.authserver.data.MemberAuthInfo
import com.friendship41.authserver.data.MemberAuthInfoRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.*
import reactor.core.publisher.Mono

@Component
class TokenHandler(@Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository) {
    private val bCryptPasswordEncoder = BCryptPasswordEncoder(4)

    fun handlePostTokenRequest(request: ServerRequest): Mono<ServerResponse> =
        request.formData().flatMap(this::createToken)




    private fun createToken(requestValueMap: MultiValueMap<String, String>?): Mono<ServerResponse> {
        val username = requestValueMap?.get("username")?.get(0) ?: return badRequest().build()
        val password = requestValueMap["password"]?.get(0) ?: return badRequest().build()

        val member = findMemberByUsername(username)
        if (!isCorrectPassword(password, member?.memberPassword)) {
            return notFound().build()
        }

        return ok().body(Mono.justOrEmpty(member), MemberAuthInfo::class.java)
    }

    private fun findMemberByUsername(username: String): MemberAuthInfo? {
        return memberAuthInfoRepository.findByMemberId(username)
                ?: memberAuthInfoRepository.findByMemberEmail(username)
    }

    private fun isCorrectPassword(reqPassword: String, dbPassword: String?): Boolean {
        return bCryptPasswordEncoder.matches(reqPassword, dbPassword)
    }
}
