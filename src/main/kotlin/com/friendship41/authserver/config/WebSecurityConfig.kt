package com.friendship41.authserver.config

import com.friendship41.authserver.service.JwtHeadersExchangeMatcher
import com.friendship41.authserver.service.JwtReactiveAuthenticationManager
import com.friendship41.authserver.service.TokenAuthenticationConverter
import com.friendship41.authserver.service.TokenProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Configuration
class WebSecurityConfiguration(
        @Autowired private val reactiveUserDetailsService: ReactiveUserDetailsService,
        @Autowired private val tokenProvider: TokenProvider) {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity, entryPoint: UnauthorizedAuthenticationEntryPoint): SecurityWebFilterChain {
        return http
                .exceptionHandling()
                .authenticationEntryPoint(entryPoint)
                .and()
                .addFilterAt(webFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .authorizeExchange().pathMatchers("/oauth/**").permitAll()
                .anyExchange().authenticated()
                .and()
                .httpBasic().disable()
                .csrf().disable()
                .formLogin().disable()
                .logout().disable()
                .build()
    }

    fun webFilter(): AuthenticationWebFilter {
        val authenticationWebFilter = AuthenticationWebFilter(repositoryReactiveAuthenticationManager())
        authenticationWebFilter.setServerAuthenticationConverter(TokenAuthenticationConverter(this.tokenProvider))
        authenticationWebFilter.setRequiresAuthenticationMatcher(JwtHeadersExchangeMatcher())
        authenticationWebFilter.setSecurityContextRepository(WebSessionServerSecurityContextRepository())
        return authenticationWebFilter
    }

    @Bean
    fun repositoryReactiveAuthenticationManager()
            = JwtReactiveAuthenticationManager(this.reactiveUserDetailsService, passwordEncoder())

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(4)
}

@Component
class UnauthorizedAuthenticationEntryPoint: ServerAuthenticationEntryPoint {
    override fun commence(exchange: ServerWebExchange, e: AuthenticationException): Mono<Void> = Mono.fromRunnable {
        exchange.response.statusCode = HttpStatus.UNAUTHORIZED
    }

}
