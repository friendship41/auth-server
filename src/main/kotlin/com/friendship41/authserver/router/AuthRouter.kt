package com.friendship41.authserver.router

import com.friendship41.authserver.handler.MemberAuthHandler
import com.friendship41.authserver.handler.TokenHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.RequestPredicates
import org.springframework.web.reactive.function.server.RouterFunctions
import org.springframework.web.reactive.function.server.router

@Configuration
class TokenRouter(private val tokenHandler: TokenHandler,
                  private val memberAuthHandler: MemberAuthHandler) {
    @Bean
    fun memberRouterFunction() = RouterFunctions.nest(
            RequestPredicates.path("/oauth"),
            router {
                listOf(
                        POST("token", tokenHandler::handlePostTokenRequest),
                        GET("token_key", tokenHandler::handleGetTokenKeyRequest)
                )})

    @Bean
    fun memberAuthRouterFunction() = RouterFunctions.nest(
            RequestPredicates.path("/authInfo"),
            router {
                listOf(
                        POST("", memberAuthHandler::handlePostAuthinfo)
                )})
}
