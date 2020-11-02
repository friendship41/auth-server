package com.friendship41.authserver.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.friendship41.authserver.data.*
import com.friendship41.authserver.service.JwtReactiveAuthenticationManager
import com.friendship41.authserver.service.JwtSignerService
import com.friendship41.authserver.service.TokenProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.reactive.function.server.body
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.toMono
import java.util.*

@Component
class TokenHandler(
        @Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository,
        @Autowired private val oauthClientDetailsRepository: OauthClientDetailsRepository,
        @Autowired private val jwtSignerService: JwtSignerService,
        @Autowired private val tokenProvider: TokenProvider,
        @Autowired private val  authenticationManager: JwtReactiveAuthenticationManager) {
    private val bCryptPasswordEncoder = BCryptPasswordEncoder(4)
    private val objectMapper = ObjectMapper()

    fun handlePostTokenRequest(request: ServerRequest): Mono<ServerResponse> {
//        val authHeader = request.headers().firstHeader("Authorization") ?: return badRequest().build()
//        val clientDetails = this.checkClientAuth(authHeader) ?: return status(HttpStatus.UNAUTHORIZED).build()

        val token = request.formData().flatMap {
            val authInfo = UsernamePasswordAuthenticationToken(it["username"]?.get(0), it["password"]?.get(0))
            val authentication = this.authenticationManager.authenticate(authInfo)
            authentication.map { this.tokenProvider.createToken(it) }
        }

        return ok().body(token)
//        return request.formData().flatMap(this::createToken)
    }

    fun testReq(request: ServerRequest): Mono<ServerResponse> = ok().build()


    // 임시
    fun checkToken(request: ServerRequest): Mono<ServerResponse> =
            request.formData().flatMap(this::temp)

    // 임시
    fun temp(requestValueMap: MultiValueMap<String, String>?): Mono<ServerResponse> {
        val a = jwtSignerService.validateJwt(requestValueMap?.get("token")?.get(0) ?: "")
        println(a.body["memberNo"])

        return ok().build()
    }

    private fun checkClientAuth(authHeader: String): OauthClientDetails? {
        val decodedAuthHeaderList = this.decodeClientAuthInfo(authHeader)
        val oauthClientDetails =
                this.oauthClientDetailsRepository.findByClientId(decodedAuthHeaderList[0]) ?: return null
        if (!this.bCryptPasswordEncoder.matches(decodedAuthHeaderList[1], oauthClientDetails.clientSecret)) {
            return null
        }

        return oauthClientDetails
    }

    /**
     * authHeader : Basic (Base64 Encoded String)
     * return : List -> clientId, clientSecret
     */
    private fun decodeClientAuthInfo(authHeader: String): List<String>
            = String(Base64.getDecoder().decode(authHeader.split("Basic ")[1])).split(":")



    private fun createToken(requestValueMap: MultiValueMap<String, String>): Mono<ServerResponse> {

        val username = requestValueMap.get("username")?.get(0) ?: return badRequest().build()
        val password = requestValueMap["password"]?.get(0) ?: return badRequest().build()

        val member = findMemberByUsername(username) ?: return status(HttpStatus.UNAUTHORIZED).build()
        if (!this.bCryptPasswordEncoder.matches(password, member.memberPassword)) {
            return status(HttpStatus.UNAUTHORIZED).build()
        }

        return ok().body(
                Mono.just(JwtTokenResponse(this.jwtSignerService.createJwtAccessToken(member))))
    }

    private fun findMemberByUsername(username: String): MemberAuthInfo? {
        return memberAuthInfoRepository.findByMemberId(username)
                ?: memberAuthInfoRepository.findByMemberEmail(username)
    }
}
