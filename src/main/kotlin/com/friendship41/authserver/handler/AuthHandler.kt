package com.friendship41.authserver.handler

import com.friendship41.authserver.data.GrantType
import com.friendship41.authserver.data.MemberAuthInfoRepository
import com.friendship41.authserver.data.ReqBodyOauthToken
import com.friendship41.authserver.data.ResBodyOauthToken
import com.friendship41.authserver.service.ClientDetailsService
import com.friendship41.authserver.service.JwtReactiveAuthenticationManager
import com.friendship41.authserver.service.TokenProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpServerErrorException
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.ok
import org.springframework.web.reactive.function.server.body
import reactor.core.publisher.Mono
import java.time.Instant
import java.util.*
import java.util.stream.Collectors

@Component
class TokenHandler(
        @Autowired private val tokenProvider: TokenProvider,
        @Autowired private val authenticationManager: JwtReactiveAuthenticationManager,
        @Autowired private val clientDetailsService: ClientDetailsService,
        @Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository) {

    fun handlePostTokenRequest(request: ServerRequest): Mono<ServerResponse> = ok().body(request
            .formData()
            .map {
                ReqBodyOauthToken(
                        GrantType.valueOf(it.getFirst("grantType")?.toUpperCase()
                                ?: throw HttpServerErrorException(HttpStatus.BAD_REQUEST)),
                        it.getFirst("username"),
                        it.getFirst("password"),
                        it.getFirst("refreshToken"),
                        it.getFirst("scope") ?: throw HttpServerErrorException(HttpStatus.BAD_REQUEST),
                        this.clientDetailsService.checkClient(request.headers()))}
            .filter { it.checkedClientDetails.scope.split(",").contains(it.scope) }
            .flatMap { reqBody ->
                when(reqBody.grantType) {
                    GrantType.PASSWORD -> this.authenticationManager
                            .authenticate(UsernamePasswordAuthenticationToken(reqBody.username, reqBody.password))
                            .map { this.createTokenResponse(it, reqBody) }
                    GrantType.REFRESH_TOKEN -> Mono.just(this.createTokenResponse(reqBody))
                }})


    // password
    private fun createTokenResponse(authentication: Authentication, reqBodyOauthToken: ReqBodyOauthToken): ResBodyOauthToken
            = ResBodyOauthToken(this.tokenProvider.createAccessToken(authentication, reqBodyOauthToken),
            "bearer",
            this.tokenProvider.createRefreshToken(authentication, reqBodyOauthToken),
            Date.from(Instant.now()
                    .plusMillis(reqBodyOauthToken.checkedClientDetails.accessTokenValidity * 1000L)).time,
            authentication.authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")))

    // refreshToken
    private fun createTokenResponse(reqBodyOauthToken: ReqBodyOauthToken): ResBodyOauthToken {
        val parsedRefreshToken = this.tokenProvider.validateJwt(reqBodyOauthToken.refreshToken
                ?: throw HttpServerErrorException(HttpStatus.BAD_REQUEST))
        val memberAuthInfo = this.memberAuthInfoRepository.findById(parsedRefreshToken.body["memberNo"].toString().toInt())
        if (memberAuthInfo.isEmpty
                || memberAuthInfo.get().memberRefreshTokenId == null
                || memberAuthInfo.get().memberRefreshTokenId != parsedRefreshToken.body["memberRefreshTokenId"]) {
            throw HttpServerErrorException(HttpStatus.BAD_REQUEST)
        }
        return this.createTokenResponse(
                UsernamePasswordAuthenticationToken(
                        parsedRefreshToken.body["memberNo"],
                        "",
                        memberAuthInfo.get().memberRole.split(",").stream()
                                .map { SimpleGrantedAuthority(it) }
                                .collect(Collectors.toList())),
                reqBodyOauthToken)
    }
}
