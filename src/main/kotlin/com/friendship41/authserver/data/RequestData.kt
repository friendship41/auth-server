package com.friendship41.authserver.data

data class ReqBodyOauthToken(
        var grantType: GrantType,
        var username: String?,
        var password: String?,
        var refreshToken: String?,
        var scope: String,
        var checkedClientDetails: OauthClientDetails
)
