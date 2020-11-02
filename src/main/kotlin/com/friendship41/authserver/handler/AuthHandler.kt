package com.friendship41.authserver.handler

import com.friendship41.authserver.data.ReqBodyOauthToken
import com.friendship41.authserver.data.ResBodyOauthToken
import com.friendship41.authserver.service.JwtReactiveAuthenticationManager
import com.friendship41.authserver.service.TokenProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
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
        @Autowired private val  authenticationManager: JwtReactiveAuthenticationManager) {

    fun handlePostTokenRequest(request: ServerRequest): Mono<ServerResponse> {
        return ok().body(request.formData()
                .map {
                    ReqBodyOauthToken(
                            it.getFirst("grantType"),
                            it.getFirst("username") ?: throw HttpServerErrorException(HttpStatus.BAD_REQUEST),
                            it.getFirst("password") ?: throw HttpServerErrorException(HttpStatus.BAD_REQUEST),
                            it.getFirst("scope")) }
                .flatMap { reqBody -> this.authenticationManager
                        .authenticate(UsernamePasswordAuthenticationToken(reqBody.username, reqBody.password))
                        .map(this::createTokenResponse)})
    }

    fun createTokenResponse(authentication: Authentication): ResBodyOauthToken = ResBodyOauthToken(
            this.tokenProvider.createToken(authentication),
            "bearer",
            this.tokenProvider.createToken(authentication),
            Date.from(Instant.now().plusMillis(300000)).time,
            authentication.authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")))

    fun testReq(request: ServerRequest): Mono<ServerResponse> = ok().build()
}
