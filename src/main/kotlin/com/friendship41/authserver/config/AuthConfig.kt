package com.friendship41.authserver.config

import com.friendship41.authserver.common.logger
import com.friendship41.authserver.service.DefaultMemberUserDetailService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.approval.ApprovalStore
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore
import javax.sql.DataSource

@Configuration
@EnableAuthorizationServer
class OAuth2AuthServerConfig(
        @Autowired private val dataSource: DataSource,
        @Autowired private val authenticationManager: AuthenticationManager,
        @Autowired private val defaultMemberUserDetailService: DefaultMemberUserDetailService
): AuthorizationServerConfigurerAdapter() {

    override fun configure(clients: ClientDetailsServiceConfigurer?) {
        clients?.jdbc(this.dataSource)
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        endpoints
                .authenticationManager(this.authenticationManager)
                .userDetailsService(this.defaultMemberUserDetailService)
                .approvalStore(this.approvalStore())
                .tokenStore(this.dbTokenStore())
    }

    override fun configure(security: AuthorizationServerSecurityConfigurer?) {
        security?.passwordEncoder(this.passwordEncoder())
    }

    @Bean
    fun dbTokenStore(): TokenStore {
        return CustomJdbcTokenStore(this.dataSource)
    }

    @Bean
    fun approvalStore(): ApprovalStore {
        return JdbcApprovalStore(this.dataSource)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder(4)
    }
}

class CustomJdbcTokenStore(dataSource: DataSource): JdbcTokenStore(dataSource) {
    private val log = logger()

    override fun readAccessToken(tokenValue: String?): OAuth2AccessToken? {

        return try {
            DefaultOAuth2AccessToken(tokenValue)
        } catch (e: EmptyResultDataAccessException) {
            if (log.isDebugEnabled) {
                log.debug("Fail to find access token, tokenValue=${tokenValue}, $e")
            }
            null
        } catch (e: IllegalArgumentException) {
            log.warn("Fail to deserialize access token, tokenValue=${tokenValue}, $e")
            null
        }
    }
}
