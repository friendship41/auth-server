package com.friendship41.authserver.service

import com.friendship41.authserver.data.OauthClientDetails
import com.friendship41.authserver.data.OauthClientDetailsRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.server.ServerRequest
import java.util.*

@Service
class ClientDetailsService(
        @Autowired private val oauthClientDetailsRepository: OauthClientDetailsRepository,
        @Autowired private val passwordEncoder: PasswordEncoder) {
    private val BASIC = "Basic "

    fun checkClient(headers: ServerRequest.Headers): OauthClientDetails {
        val authHeader = headers.firstHeader("Authorization")
                ?: throw BadCredentialsException("Invalid Client, Authorization is null")
        if (authHeader.length <= BASIC.length || authHeader.substring(0, BASIC.length) != BASIC) {
            throw BadCredentialsException("Invalid header, authHeader=$authHeader")
        }
        val requestClientInfo = String(Base64.getDecoder().decode(authHeader.substring(BASIC.length))).split(":")

        val dbClientDetails = this.oauthClientDetailsRepository.findByClientId(requestClientInfo[0])
                ?: throw BadCredentialsException("No Client exsist, clientId=${requestClientInfo[0]}")

        if (!this.passwordEncoder.matches(requestClientInfo[1], dbClientDetails.clientSecret)) {
            throw BadCredentialsException("Not Valid Client Secret")
        }

        return dbClientDetails
    }
}
