class TspiException(Exception):
    pass

class TSS_E_BASE(TspiException):
    pass

class TSS_E_FAIL(TspiException):
    pass

class TSS_E_BAD_PARAMETER(TspiException):
    pass

class TSS_E_INTERNAL_ERROR(TspiException):
    pass

class TSS_E_OUTOFMEMORY(TspiException):
    pass

class TSS_E_NOTIMPL(TspiException):
    pass

class TSS_E_KEY_ALREADY_REGISTERED(TspiException):
    pass

class TSS_E_TPM_UNEXPECTED(TspiException):
    pass

class TSS_E_COMM_FAILURE(TspiException):
    pass

class TSS_E_TIMEOUT(TspiException):
    pass

class TSS_E_TPM_UNSUPPORTED_FEATURE(TspiException):
    pass

class TSS_E_CANCELED(TspiException):
    pass

class TSS_E_PS_KEY_NOTFOUND(TspiException):
    pass

class TSS_E_PS_KEY_EXISTS(TspiException):
    pass

class TSS_E_PS_BAD_KEY_STATE(TspiException):
    pass

class TSS_E_INVALID_OBJECT_TYPE(TspiException):
    pass

class TSS_E_NO_CONNECTION(TspiException):
    pass

class TSS_E_CONNECTION_FAILED(TspiException):
    pass

class TSS_E_CONNECTION_BROKEN(TspiException):
    pass

class TSS_E_HASH_INVALID_ALG(TspiException):
    pass

class TSS_E_HASH_INVALID_LENGTH(TspiException):
    pass

class TSS_E_HASH_NO_DATA(TspiException):
    pass

class TSS_E_INVALID_ATTRIB_FLAG(TspiException):
    pass

class TSS_E_INVALID_ATTRIB_SUBFLAG(TspiException):
    pass

class TSS_E_INVALID_ATTRIB_DATA(TspiException):
    pass

class TSS_E_INVALID_OBJECT_INIT_FLAG(TspiException):
    pass

class TSS_E_INVALID_OBJECT_INITFLAG(TspiException):
    pass

class TSS_E_NO_PCRS_SET(TspiException):
    pass

class TSS_E_KEY_NOT_LOADED(TspiException):
    pass

class TSS_E_KEY_NOT_SET(TspiException):
    pass

class TSS_E_VALIDATION_FAILED(TspiException):
    pass

class TSS_E_TSP_AUTHREQUIRED(TspiException):
    pass

class TSS_E_TSP_AUTH2REQUIRED(TspiException):
    pass

class TSS_E_TSP_AUTHFAIL(TspiException):
    pass

class TSS_E_TSP_AUTH2FAIL(TspiException):
    pass

class TSS_E_KEY_NO_MIGRATION_POLICY(TspiException):
    pass

class TSS_E_POLICY_NO_SECRET(TspiException):
    pass

class TSS_E_INVALID_OBJ_ACCESS(TspiException):
    pass

class TSS_E_INVALID_ENCSCHEME(TspiException):
    pass

class TSS_E_INVALID_SIGSCHEME(TspiException):
    pass

class TSS_E_ENC_INVALID_LENGTH(TspiException):
    pass

class TSS_E_ENC_NO_DATA(TspiException):
    pass

class TSS_E_ENC_INVALID_TYPE(TspiException):
    pass

class TSS_E_INVALID_KEYUSAGE(TspiException):
    pass

class TSS_E_VERIFICATION_FAILED(TspiException):
    pass

class TSS_E_HASH_NO_IDENTIFIER(TspiException):
    pass

class TSS_E_INVALID_HANDLE(TspiException):
    pass

class TSS_E_SILENT_CONTEXT(TspiException):
    pass

class TSS_E_EK_CHECKSUM(TspiException):
    pass

class TSS_E_DELEGATION_NOTSET(TspiException):
    pass

class TSS_E_DELFAMILY_NOTFOUND(TspiException):
    pass

class TSS_E_DELFAMILY_ROWEXISTS(TspiException):
    pass

class TSS_E_VERSION_MISMATCH(TspiException):
    pass

class TSS_E_DAA_AR_DECRYPTION_ERROR(TspiException):
    pass

class TSS_E_DAA_AUTHENTICATION_ERROR(TspiException):
    pass

class TSS_E_DAA_CHALLENGE_RESPONSE_ERROR(TspiException):
    pass

class TSS_E_DAA_CREDENTIAL_PROOF_ERROR(TspiException):
    pass

class TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR(TspiException):
    pass

class TSS_E_DAA_ISSUER_KEY_ERROR(TspiException):
    pass

class TSS_E_DAA_PSEUDONYM_ERROR(TspiException):
    pass

class TSS_E_INVALID_RESOURCE(TspiException):
    pass

class TSS_E_NV_AREA_EXIST(TspiException):
    pass

class TSS_E_NV_AREA_NOT_EXIST(TspiException):
    pass

class TSS_E_TSP_TRANS_AUTHFAIL(TspiException):
    pass

class TSS_E_TSP_TRANS_AUTHREQUIRED(TspiException):
    pass

class TSS_E_TSP_TRANS_NOTEXCLUSIVE(TspiException):
    pass

class TSS_E_TSP_TRANS_FAIL(TspiException):
    pass

class TSS_E_TSP_TRANS_NO_PUBKEY(TspiException):
    pass

class TSS_E_NO_ACTIVE_COUNTER(TspiException):
    pass

class TpmException(Exception):
    pass

class TPM_E_BASE(TpmException):
    pass

class TPM_E_NON_FATAL(TpmException):
    pass

class TPM_E_AUTHFAIL(TpmException):
    pass

class TPM_E_BADINDEX(TpmException):
    pass

class TPM_E_BAD_PARAMETER(TpmException):
    pass

class TPM_E_AUDITFAILURE(TpmException):
    pass

class TPM_E_CLEAR_DISABLED(TpmException):
    pass

class TPM_E_DEACTIVATED(TpmException):
    pass

class TPM_E_DISABLED(TpmException):
    pass

class TPM_E_DISABLED_CMD(TpmException):
    pass

class TPM_E_FAIL(TpmException):
    pass

class TPM_E_BAD_ORDINAL(TpmException):
    pass

class TPM_E_INSTALL_DISABLED(TpmException):
    pass

class TPM_E_INVALID_KEYHANDLE(TpmException):
    pass

class TPM_E_KEYNOTFOUND(TpmException):
    pass

class TPM_E_INAPPROPRIATE_ENC(TpmException):
    pass

class TPM_E_MIGRATEFAIL(TpmException):
    pass

class TPM_E_INVALID_PCR_INFO(TpmException):
    pass

class TPM_E_NOSPACE(TpmException):
    pass

class TPM_E_NOSRK(TpmException):
    pass

class TPM_E_NOTSEALED_BLOB(TpmException):
    pass

class TPM_E_OWNER_SET(TpmException):
    pass

class TPM_E_RESOURCES(TpmException):
    pass

class TPM_E_SHORTRANDOM(TpmException):
    pass

class TPM_E_SIZE(TpmException):
    pass

class TPM_E_WRONGPCRVAL(TpmException):
    pass

class TPM_E_BAD_PARAM_SIZE(TpmException):
    pass

class TPM_E_SHA_THREAD(TpmException):
    pass

class TPM_E_SHA_ERROR(TpmException):
    pass

class TPM_E_FAILEDSELFTEST(TpmException):
    pass

class TPM_E_AUTH2FAIL(TpmException):
    pass

class TPM_E_BADTAG(TpmException):
    pass

class TPM_E_IOERROR(TpmException):
    pass

class TPM_E_ENCRYPT_ERROR(TpmException):
    pass

class TPM_E_DECRYPT_ERROR(TpmException):
    pass

class TPM_E_INVALID_AUTHHANDLE(TpmException):
    pass

class TPM_E_NO_ENDORSEMENT(TpmException):
    pass

class TPM_E_INVALID_KEYUSAGE(TpmException):
    pass

class TPM_E_WRONG_ENTITYTYPE(TpmException):
    pass

class TPM_E_INVALID_POSTINIT(TpmException):
    pass

class TPM_E_INAPPROPRIATE_SIG(TpmException):
    pass

class TPM_E_BAD_KEY_PROPERTY(TpmException):
    pass

class TPM_E_BAD_MIGRATION(TpmException):
    pass

class TPM_E_BAD_SCHEME(TpmException):
    pass

class TPM_E_BAD_DATASIZE(TpmException):
    pass

class TPM_E_BAD_MODE(TpmException):
    pass

class TPM_E_BAD_PRESENCE(TpmException):
    pass

class TPM_E_BAD_VERSION(TpmException):
    pass

class TPM_E_NO_WRAP_TRANSPORT(TpmException):
    pass

class TPM_E_AUDITFAIL_UNSUCCESSFUL(TpmException):
    pass

class TPM_E_AUDITFAIL_SUCCESSFUL(TpmException):
    pass

class TPM_E_NOTRESETABLE(TpmException):
    pass

class TPM_E_NOTLOCAL(TpmException):
    pass

class TPM_E_BAD_TYPE(TpmException):
    pass

class TPM_E_INVALID_RESOURCE(TpmException):
    pass

class TPM_E_NOTFIPS(TpmException):
    pass

class TPM_E_INVALID_FAMILY(TpmException):
    pass

class TPM_E_NO_NV_PERMISSION(TpmException):
    pass

class TPM_E_REQUIRES_SIGN(TpmException):
    pass

class TPM_E_KEY_NOTSUPPORTED(TpmException):
    pass

class TPM_E_AUTH_CONFLICT(TpmException):
    pass

class TPM_E_AREA_LOCKED(TpmException):
    pass

class TPM_E_BAD_LOCALITY(TpmException):
    pass

class TPM_E_READ_ONLY(TpmException):
    pass

class TPM_E_PER_NOWRITE(TpmException):
    pass

class TPM_E_FAMILYCOUNT(TpmException):
    pass

class TPM_E_WRITE_LOCKED(TpmException):
    pass

class TPM_E_BAD_ATTRIBUTES(TpmException):
    pass

class TPM_E_INVALID_STRUCTURE(TpmException):
    pass

class TPM_E_KEY_OWNER_CONTROL(TpmException):
    pass

class TPM_E_BAD_COUNTER(TpmException):
    pass

class TPM_E_NOT_FULLWRITE(TpmException):
    pass

class TPM_E_CONTEXT_GAP(TpmException):
    pass

class TPM_E_MAXNVWRITES(TpmException):
    pass

class TPM_E_NOOPERATOR(TpmException):
    pass

class TPM_E_RESOURCEMISSING(TpmException):
    pass

class TPM_E_DELEGATE_LOCK(TpmException):
    pass

class TPM_E_DELEGATE_FAMILY(TpmException):
    pass

class TPM_E_DELEGATE_ADMIN(TpmException):
    pass

class TPM_E_TRANSPORT_NOTEXCLUSIVE(TpmException):
    pass

class TPM_E_OWNER_CONTROL(TpmException):
    pass

class TPM_E_DAA_RESOURCES(TpmException):
    pass

class TPM_E_DAA_INPUT_DATA0(TpmException):
    pass

class TPM_E_DAA_INPUT_DATA1(TpmException):
    pass

class TPM_E_DAA_ISSUER_SETTINGS(TpmException):
    pass

class TPM_E_DAA_TPM_SETTINGS(TpmException):
    pass

class TPM_E_DAA_STAGE(TpmException):
    pass

class TPM_E_DAA_ISSUER_VALIDITY(TpmException):
    pass

class TPM_E_DAA_WRONG_W(TpmException):
    pass

class TPM_E_BAD_HANDLE(TpmException):
    pass

class TPM_E_BAD_DELEGATE(TpmException):
    pass

class TPM_E_BADCONTEXT(TpmException):
    pass

class TPM_E_TOOMANYCONTEXTS(TpmException):
    pass

class TPM_E_MA_TICKET_SIGNATURE(TpmException):
    pass

class TPM_E_MA_DESTINATION(TpmException):
    pass

class TPM_E_MA_SOURCE(TpmException):
    pass

class TPM_E_MA_AUTHORITY(TpmException):
    pass

class TPM_E_PERMANENTEK(TpmException):
    pass

class TPM_E_BAD_SIGNATURE(TpmException):
    pass

class TPM_E_NOCONTEXTSPACE(TpmException):
    pass

class TPM_E_RETRY(TpmException):
    pass

class TPM_E_NEEDS_SELFTEST(TpmException):
    pass

class TPM_E_DOING_SELFTEST(TpmException):
    pass

class TPM_E_DEFEND_LOCK_RUNNING(TpmException):
    pass
