package com.friendship41.authserver.service

import com.friendship41.authserver.data.MemberAuthInfo
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.security.KeyPair
import java.time.Instant
import java.util.*

@Service
class JwtSignerService {
    val keyPair: KeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256)

    fun createJwtAccessToken(member: MemberAuthInfo): String = Jwts.builder()
            .signWith(this.keyPair.private, SignatureAlgorithm.RS256)
            .claim("memberNo", member.memberNo.toString())
            .setIssuer("friendship41")
            .setExpiration(Date.from(Instant.now().plusMillis(300000)))
            .setIssuedAt(Date.from(Instant.now()))
            .compact()

    fun validateJwt(jwt: String): Jws<Claims> = Jwts.parserBuilder()
            .setSigningKey(this.keyPair.public)
            .build()
            .parseClaimsJws(jwt)
}
