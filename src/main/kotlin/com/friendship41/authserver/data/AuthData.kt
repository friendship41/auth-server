package com.friendship41.authserver.data

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class MemberAuthInfo(
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        var memberNo: Int?,
        var memberAuthKey: String,
        var memberPassword: String,
        var memberRole: String,
        var memberRefreshTokenId: String?
)

@Repository
interface MemberAuthInfoRepository: JpaRepository<MemberAuthInfo, Int> {
        fun findByMemberAuthKey(memberAuthKey: String): MemberAuthInfo?
}

@Entity
data class OauthClientDetails(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var clientId: String,
        var resourceIds: String?,
        var clientSecret: String,
        var scope: String,
        var authorizedGrantTypes: String,
        var webServerRedirectUri: String?,
        var authorities: String?,
        var accessTokenValidity: Int,
        var refreshTokenValidity: Int,
        var additionalInformation: String?,
        var autoapprove: String
)

@Repository
interface OauthClientDetailsRepository: JpaRepository<OauthClientDetails, String> {
        fun findByClientId(clientId: String): OauthClientDetails?
}
