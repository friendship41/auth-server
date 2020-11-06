package com.friendship41.authserver.data

data class ResBodyOauthToken(
        var accessToken: String,
        var tokenType: String,
        var refreshToken: String,
        var expiresIn: Long,
        var roles: String
)

data class ResBodyTokenKey(
        var alg: String,
        var value: String
)
