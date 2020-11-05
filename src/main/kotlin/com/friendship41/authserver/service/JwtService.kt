package com.friendship41.authserver.service

import com.friendship41.authserver.common.logger
import com.friendship41.authserver.data.MemberAuthInfoRepository
import com.friendship41.authserver.data.ReqBodyOauthToken
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SignatureException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
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
import org.springframework.web.client.HttpServerErrorException
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.io.File
import java.io.FileInputStream
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.time.Instant
import java.util.*
import java.util.stream.Collectors
import javax.annotation.PostConstruct
import kotlin.collections.ArrayList

@Component
class TokenProvider(@Autowired private val memberAuthInfoRepository: MemberAuthInfoRepository) {
    lateinit var keyPair: KeyPair

    @Value("\${spring.profiles.active}")
    private val activeProfile: String? = null

    @Value("\${server.ssl.key-store}")
    private val keyStorePath: String? = null

    @Value("\${server.ssl.key-store-type}")
    private val keyStoreType: String? = null

    @Value("\${server.ssl.key-store-password}")
    private val keyStorePassword: String? = null

    @Value("\${server.ssl.key-alias}")
    private val keyAlias: String? = null

    @PostConstruct
    fun setKeyPair() {
        val keyStore = KeyStore.getInstance(keyStoreType)
        when (activeProfile?.toUpperCase()) {
            "DEV" -> keyStore.load(
                    FileInputStream(ClassPathResource("keystore.p12").file),
                    keyStorePassword?.toCharArray())
            "RELEASE" -> keyStore.load(FileInputStream(File(keyStorePath ?: "")), keyStorePassword?.toCharArray())
        }

        this.keyPair = KeyPair(
                keyStore.getCertificate(keyAlias).publicKey,
                keyStore.getKey(keyAlias, keyStorePassword?.toCharArray()) as PrivateKey)
    }

    fun createAccessToken(authentication: Authentication, reqBodyOauthToken: ReqBodyOauthToken): String = Jwts.builder()
            .signWith(this.keyPair.private, SignatureAlgorithm.RS256)
            .claim("memberNo", authentication.name)
            .claim("authorities", authentication.authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
            .claim("scope", reqBodyOauthToken.checkedClientDetails.scope.split(","))
            .setIssuer("friendship41")
            .setExpiration(Date.from(Instant.now().plusMillis(
                    reqBodyOauthToken.checkedClientDetails.accessTokenValidity*1000L)))
            .setIssuedAt(Date.from(Instant.now()))
            .compact()

    fun createRefreshToken(authentication: Authentication, reqBodyOauthToken: ReqBodyOauthToken): String {
        val memberAuthInfo
                = this.memberAuthInfoRepository.findById(authentication.name.toInt())
        if (!memberAuthInfo.isPresent) {
            throw HttpServerErrorException(HttpStatus.BAD_REQUEST)
        }
        memberAuthInfo.get().memberRefreshTokenId = UUID.randomUUID().toString()
        this.memberAuthInfoRepository.save(memberAuthInfo.get())
        return Jwts.builder()
                .signWith(this.keyPair.private, SignatureAlgorithm.RS256)
                .claim("memberNo", authentication.name)
                .claim("memberRefreshTokenId", memberAuthInfo.get().memberRefreshTokenId)
                .setIssuer("friendship41")
                .setExpiration(Date.from(Instant.now().plusMillis(
                        reqBodyOauthToken.checkedClientDetails.refreshTokenValidity*1000L)))
                .setIssuedAt(Date.from(Instant.now()))
                .compact()
    }

    fun getAuthentication(token: String?): Authentication {
        val jwtToken = token ?: throw BadCredentialsException("Invalid token: $token")
        val claims = validateJwt(jwtToken)

        val authorities = (claims.body["authorities"] as ArrayList<*>).stream()
                .map{SimpleGrantedAuthority(it.toString())}
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
