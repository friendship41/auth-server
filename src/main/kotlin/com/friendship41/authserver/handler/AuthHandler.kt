package com.friendship41.authserver.handler

import com.friendship41.authserver.data.JwtTokenResponse
import com.friendship41.authserver.data.MemberAuthInfo
import com.friendship41.authserver.data.MemberAuthInfoRepository
import com.friendship41.authserver.service.JwtSignerService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.reactive.function.server.body
import reactor.core.publisher.Mono

@Component
class TokenHandler(
        @Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository,
        @Autowired private val jwtSignerService: JwtSignerService) {
    private val bCryptPasswordEncoder = BCryptPasswordEncoder(4)

    fun handlePostTokenRequest(request: ServerRequest): Mono<ServerResponse> =
        request.formData().flatMap(this::createToken)

    // 임시
    fun checkToken(request: ServerRequest): Mono<ServerResponse> =
            request.formData().flatMap(this::temp)

    // 임시
    fun temp(requestValueMap: MultiValueMap<String, String>?): Mono<ServerResponse> {
        val a = jwtSignerService.validateJwt(requestValueMap?.get("token")?.get(0) ?: "")
        println(a.body["memberNo"])

        return ok().build()
    }


    private fun createToken(requestValueMap: MultiValueMap<String, String>?): Mono<ServerResponse> {
        val username = requestValueMap?.get("username")?.get(0) ?: return badRequest().build()
        val password = requestValueMap["password"]?.get(0) ?: return badRequest().build()

        val member = findMemberByUsername(username) ?: return notFound().build()
        if (!isCorrectPassword(password, member.memberPassword)) {
            return notFound().build()
        }

        return ok().body(
                Mono.just(JwtTokenResponse(this.jwtSignerService.createJwtAccessToken(member))))
    }

    private fun findMemberByUsername(username: String): MemberAuthInfo? {
        return memberAuthInfoRepository.findByMemberId(username)
                ?: memberAuthInfoRepository.findByMemberEmail(username)
    }

    private fun isCorrectPassword(reqPassword: String, dbPassword: String?): Boolean {
        return bCryptPasswordEncoder.matches(reqPassword, dbPassword)
    }
}
