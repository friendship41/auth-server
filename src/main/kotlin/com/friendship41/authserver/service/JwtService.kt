package com.friendship41.authserver.service

import com.friendship41.authserver.common.logger
import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.security.KeyPair
import java.time.Instant
import java.util.*
import java.util.stream.Collectors

@Component
class TokenProvider {
    val keyPair: KeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256)

    fun createToken(authentication: Authentication): String = Jwts.builder()
            .signWith(this.keyPair.private, SignatureAlgorithm.RS256)
            .claim("memberNo", authentication.name)
            .claim("roles", authentication.authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")))
            .setIssuer("friendship41")
            .setExpiration(Date.from(Instant.now().plusMillis(300000)))
            .setIssuedAt(Date.from(Instant.now()))
            .compact()

    fun getAuthentication(token: String?): Authentication {
        val jwtToken = token ?: throw BadCredentialsException("Invalid token: $token")
        val claims = validateJwt(jwtToken)

        val authorities = claims.body["roles"].toString().split(",").stream()
                .map{SimpleGrantedAuthority(it)}
                .collect(Collectors.toList())

        return UsernamePasswordAuthenticationToken(
                User(
                        claims.body["memberNo"].toString(),
                        "",
                        authorities),
                jwtToken,
                authorities
        )
    }

    fun validateJwt(jwtToken: String): Jws<Claims> = try {
        Jwts.parserBuilder()
                .setSigningKey(this.keyPair.public)
                .build()
                 .parseClaimsJws(jwtToken)
    } catch (e: SignatureException) {
        logger().info("Invalid JWT signature: $jwtToken")
        throw BadCredentialsException("Invalid JWT signature: $jwtToken")
    } catch (e: MalformedJwtException) {
        logger().info("Invalid token: $jwtToken")
        throw BadCredentialsException("Invalid token: $jwtToken")
    } catch (e: ExpiredJwtException) {
        logger().info("Expired JWT token: $jwtToken")
        throw BadCredentialsException("Expired JWT token: $jwtToken")
    } catch (e: UnsupportedJwtException) {
        logger().info("Unsupported JWT token: $jwtToken")
        throw BadCredentialsException("Unsupported JWT token: $jwtToken")
    } catch (e: IllegalArgumentException) {
        logger().info("JWT token compact of handler are invalid: $jwtToken")
        throw BadCredentialsException("JWT token compact of handler are invalid: $jwtToken")
    } catch (e: Exception) {
        logger().info("Invalid token: $jwtToken")
        throw BadCredentialsException("Invalid token: $jwtToken")
    }
}

class JwtReactiveAuthenticationManager(
        private val userDetailsService: ReactiveUserDetailsService,
        private val passwordEncoder: PasswordEncoder): ReactiveAuthenticationManager {


    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        if (authentication.isAuthenticated) {
            return Mono.just(authentication)
        }

        return Mono.just(authentication)
                .switchIfEmpty(Mono.error(BadCredentialsException("Invalid Credentials")))
                .cast(UsernamePasswordAuthenticationToken::class.java)
                .flatMap(this::authenticateToken)
                .publishOn(Schedulers.parallel())
                .onErrorResume{ Mono.error(BadCredentialsException("Invalid Credentials")) }
                .filter{ this.passwordEncoder.matches(authentication.credentials.toString(), it.password) }
                .switchIfEmpty(Mono.error(BadCredentialsException("Invalid Credentials")))
                .map {
                    UsernamePasswordAuthenticationToken(it.username, authentication.credentials, it.authorities)
                }
    }

    private fun authenticateToken(authenticationToken: UsernamePasswordAuthenticationToken): Mono<UserDetails>? {
        val username = authenticationToken.name
        if (authenticationToken.name == null && SecurityContextHolder.getContext().authentication == null) {
            return null
        }
        logger().info("auth start username: $username")

        return this.userDetailsService.findByUsername(username)
    }
}

class JwtHeadersExchangeMatcher: ServerWebExchangeMatcher {
    override fun matches(exchange: ServerWebExchange): Mono<ServerWebExchangeMatcher.MatchResult> =
            Mono.just(exchange)
                    .map(ServerWebExchange::getRequest)
                    .map(ServerHttpRequest::getHeaders)
                    .filter{ it.containsKey(HttpHeaders.AUTHORIZATION)}
                    .flatMap { ServerWebExchangeMatcher.MatchResult.match() }
                    .switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch())

}

class TokenAuthenticationConverter(private val tokenProvider: TokenProvider): ServerAuthenticationConverter {
    private val BEARER = "Bearer "

    override fun convert(exchange: ServerWebExchange): Mono<Authentication> =
            Mono.justOrEmpty(exchange)
                    .filter{ it.request.path.toString() != "/oauth/token" }
                    .map{ it.request.headers.getFirst(HttpHeaders.AUTHORIZATION) ?: ""}
                    .filter(Objects::nonNull)
                    .filter{ it.length > BEARER.length && it.substring(0, BEARER.length) == BEARER }
                    .map{ it.substring(BEARER.length) }
                    .filter{ it != null && it != "" }
                    .map(this.tokenProvider::getAuthentication)
                    .filter(Objects::nonNull)

}
