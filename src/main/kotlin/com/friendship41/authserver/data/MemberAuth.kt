package com.friendship41.authserver.data

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class MemberAuthInfo(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var memberNo: Int,
        var memberId: String,
        var memberEmail: String,
        var memberPassword: String,
        var memberJoinDate: Date,
        var memberRole: String
)

@Repository
interface MemberAuthInfoRepository: JpaRepository<MemberAuthInfo, Int> {
        fun findByMemberId(memberId: String): MemberAuthInfo?
        fun findByMemberEmail(memberEmail: String): MemberAuthInfo?
}
