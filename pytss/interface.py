import functools
import os
from tspi_exceptions import *

from cffi import FFI, VerificationError
INTERFACE_H = os.path.dirname(os.path.abspath(__file__)) + '/interface.h'
__all__ = ["ffi", "lib"]

# Setup CFFI with libtspi
ffi = FFI()

ffi.cdef(open(INTERFACE_H, 'r').read())
tss_lib = ffi.verify('#include <trousers/tss.h>', libraries=['tspi'])

def wrap_libtspi_func(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        if ret == 0:
            return True
        if (ret & 0x3000):
            ret = ret & ~0x3000
            if ret == tss_lib.TSS_E_FAIL:
                raise TSS_E_FAIL
            elif ret == tss_lib.TSS_E_BAD_PARAMETER:
                raise TSS_E_BAD_PARAMETER
            elif ret == tss_lib.TSS_E_INTERNAL_ERROR:
                raise TSS_E_INTERNAL_ERROR
            elif ret == tss_lib.TSS_E_OUTOFMEMORY:
                raise TSS_E_OUTOFMEMORY
            elif ret == tss_lib.TSS_E_NOTIMPL:
                raise TSS_E_NOTIMPL
            elif ret == tss_lib.TSS_E_KEY_ALREADY_REGISTERED:
                raise TSS_E_KEY_ALREADY_REGISTERED
            elif ret == tss_lib.TSS_E_TPM_UNEXPECTED:
                raise TSS_E_TPM_UNEXPECTED
            elif ret == tss_lib.TSS_E_COMM_FAILURE:
                raise TSS_E_COMM_FAILURE
            elif ret == tss_lib.TSS_E_TIMEOUT:
                raise TSS_E_TIMEOUT
            elif ret == tss_lib.TSS_E_TPM_UNSUPPORTED_FEATURE:
                raise TSS_E_TPM_UNSUPPORTED_FEATURE
            elif ret == tss_lib.TSS_E_CANCELED:
                raise TSS_E_CANCELED
            elif ret == tss_lib.TSS_E_PS_KEY_NOTFOUND:
                raise TSS_E_PS_KEY_NOTFOUND
            elif ret == tss_lib.TSS_E_PS_KEY_EXISTS:
                raise TSS_E_PS_KEY_EXISTS
            elif ret == tss_lib.TSS_E_PS_BAD_KEY_STATE:
                raise TSS_E_PS_BAD_KEY_STATE
            elif ret == tss_lib.TSS_E_INVALID_OBJECT_TYPE:
                raise TSS_E_INVALID_OBJECT_TYPE
            elif ret == tss_lib.TSS_E_NO_CONNECTION:
                raise TSS_E_NO_CONNECTION
            elif ret == tss_lib.TSS_E_CONNECTION_FAILED:
                raise TSS_E_CONNECTION_FAILED
            elif ret == tss_lib.TSS_E_CONNECTION_BROKEN:
                raise TSS_E_CONNECTION_BROKEN
            elif ret == tss_lib.TSS_E_HASH_INVALID_ALG:
                raise TSS_E_HASH_INVALID_ALG
            elif ret == tss_lib.TSS_E_HASH_INVALID_LENGTH:
                raise TSS_E_HASH_INVALID_LENGTH
            elif ret == tss_lib.TSS_E_HASH_NO_DATA:
                raise TSS_E_HASH_NO_DATA
            elif ret == tss_lib.TSS_E_INVALID_ATTRIB_FLAG:
                raise TSS_E_INVALID_ATTRIB_FLAG
            elif ret == tss_lib.TSS_E_INVALID_ATTRIB_SUBFLAG:
                raise TSS_E_INVALID_ATTRIB_SUBFLAG
            elif ret == tss_lib.TSS_E_INVALID_ATTRIB_DATA:
                raise TSS_E_INVALID_ATTRIB_DATA
            elif ret == tss_lib.TSS_E_INVALID_OBJECT_INITFLAG:
                raise TSS_E_INVALID_OBJECT_INITFLAG
            elif ret == tss_lib.TSS_E_NO_PCRS_SET:
                raise TSS_E_NO_PCRS_SET
            elif ret == tss_lib.TSS_E_KEY_NOT_LOADED:
                raise TSS_E_KEY_NOT_LOADED
            elif ret == tss_lib.TSS_E_KEY_NOT_SET:
                raise TSS_E_KEY_NOT_SET
            elif ret == tss_lib.TSS_E_VALIDATION_FAILED:
                raise TSS_E_VALIDATION_FAILED
            elif ret == tss_lib.TSS_E_TSP_AUTHREQUIRED:
                raise TSS_E_TSP_AUTHREQUIRED
            elif ret == tss_lib.TSS_E_TSP_AUTH2REQUIRED:
                raise TSS_E_TSP_AUTH2REQUIRED
            elif ret == tss_lib.TSS_E_TSP_AUTHFAIL:
                raise TSS_E_TSP_AUTHFAIL
            elif ret == tss_lib.TSS_E_TSP_AUTH2FAIL:
                raise TSS_E_TSP_AUTH2FAIL
            elif ret == tss_lib.TSS_E_KEY_NO_MIGRATION_POLICY:
                raise TSS_E_KEY_NO_MIGRATION_POLICY
            elif ret == tss_lib.TSS_E_POLICY_NO_SECRET:
                raise TSS_E_POLICY_NO_SECRET
            elif ret == tss_lib.TSS_E_INVALID_OBJ_ACCESS:
                raise TSS_E_INVALID_OBJ_ACCESS
            elif ret == tss_lib.TSS_E_INVALID_ENCSCHEME:
                raise TSS_E_INVALID_ENCSCHEME
            elif ret == tss_lib.TSS_E_INVALID_SIGSCHEME:
                raise TSS_E_INVALID_SIGSCHEME
            elif ret == tss_lib.TSS_E_ENC_INVALID_LENGTH:
                raise TSS_E_ENC_INVALID_LENGTH
            elif ret == tss_lib.TSS_E_ENC_NO_DATA:
                raise TSS_E_ENC_NO_DATA
            elif ret == tss_lib.TSS_E_ENC_INVALID_TYPE:
                raise TSS_E_ENC_INVALID_TYPE
            elif ret == tss_lib.TSS_E_INVALID_KEYUSAGE:
                raise TSS_E_INVALID_KEYUSAGE
            elif ret == tss_lib.TSS_E_VERIFICATION_FAILED:
                raise TSS_E_VERIFICATION_FAILED
            elif ret == tss_lib.TSS_E_HASH_NO_IDENTIFIER:
                raise TSS_E_HASH_NO_IDENTIFIER
            elif ret == tss_lib.TSS_E_INVALID_HANDLE:
                raise TSS_E_INVALID_HANDLE
            elif ret == tss_lib.TSS_E_SILENT_CONTEXT:
                raise TSS_E_SILENT_CONTEXT
            elif ret == tss_lib.TSS_E_EK_CHECKSUM:
                raise TSS_E_EK_CHECKSUM
            elif ret == tss_lib.TSS_E_DELEGATION_NOTSET:
                raise TSS_E_DELEGATION_NOTSET
            elif ret == tss_lib.TSS_E_DELFAMILY_NOTFOUND:
                raise TSS_E_DELFAMILY_NOTFOUND
            elif ret == tss_lib.TSS_E_DELFAMILY_ROWEXISTS:
                raise TSS_E_DELFAMILY_ROWEXISTS
            elif ret == tss_lib.TSS_E_VERSION_MISMATCH:
                raise TSS_E_VERSION_MISMATCH
            elif ret == tss_lib.TSS_E_DAA_AR_DECRYPTION_ERROR:
                raise TSS_E_DAA_AR_DECRYPTION_ERROR
            elif ret == tss_lib.TSS_E_DAA_AUTHENTICATION_ERROR:
                raise TSS_E_DAA_AUTHENTICATION_ERROR
            elif ret == tss_lib.TSS_E_DAA_CHALLENGE_RESPONSE_ERROR:
                raise TSS_E_DAA_CHALLENGE_RESPONSE_ERROR
            elif ret == tss_lib.TSS_E_DAA_CREDENTIAL_PROOF_ERROR:
                raise TSS_E_DAA_CREDENTIAL_PROOF_ERROR
            elif ret == tss_lib.TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR:
                raise TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR
            elif ret == tss_lib.TSS_E_DAA_ISSUER_KEY_ERROR:
                raise TSS_E_DAA_ISSUER_KEY_ERROR
            elif ret == tss_lib.TSS_E_DAA_PSEUDONYM_ERROR:
                raise TSS_E_DAA_PSEUDONYM_ERROR
            elif ret == tss_lib.TSS_E_INVALID_RESOURCE:
                raise TSS_E_INVALID_RESOURCE
            elif ret == tss_lib.TSS_E_NV_AREA_EXIST:
                raise TSS_E_NV_AREA_EXIST
            elif ret == tss_lib.TSS_E_NV_AREA_NOT_EXIST:
                raise TSS_E_NV_AREA_NOT_EXIST
            elif ret == tss_lib.TSS_E_TSP_TRANS_AUTHFAIL:
                raise TSS_E_TSP_TRANS_AUTHFAIL
            elif ret == tss_lib.TSS_E_TSP_TRANS_AUTHREQUIRED:
                raise TSS_E_TSP_TRANS_AUTHREQUIRED
            elif ret == tss_lib.TSS_E_TSP_TRANS_NOTEXCLUSIVE:
                raise TSS_E_TSP_TRANS_NOTEXCLUSIVE
            elif ret == tss_lib.TSS_E_TSP_TRANS_FAIL:
                raise TSS_E_TSP_TRANS_FAIL
            elif ret == tss_lib.TSS_E_TSP_TRANS_NO_PUBKEY:
                raise TSS_E_TSP_TRANS_NO_PUBKEY
            elif ret == tss_lib.TSS_E_NO_ACTIVE_COUNTER:
                raise TSS_E_NO_ACTIVE_COUNTER
            else:
                raise TspiException("Unknown Error %x" % ret)
        else:
            if ret == tss_lib.TPM_E_NON_FATAL:
                raise TPM_E_NON_FATAL
            elif ret == tss_lib.TPM_E_AUTHFAIL:
                raise TPM_E_AUTHFAIL
            elif ret == tss_lib.TPM_E_BADINDEX:
                raise TPM_E_BADINDEX
            elif ret == tss_lib.TPM_E_BAD_PARAMETER:
                raise TPM_E_BAD_PARAMETER
            elif ret == tss_lib.TPM_E_AUDITFAILURE:
                raise TPM_E_AUDITFAILURE
            elif ret == tss_lib.TPM_E_CLEAR_DISABLED:
                raise TPM_E_CLEAR_DISABLED
            elif ret == tss_lib.TPM_E_DEACTIVATED:
                raise TPM_E_DEACTIVATED
            elif ret == tss_lib.TPM_E_DISABLED:
                raise TPM_E_DISABLED
            elif ret == tss_lib.TPM_E_DISABLED_CMD:
                raise TPM_E_DISABLED_CMD
            elif ret == tss_lib.TPM_E_FAIL:
                raise TPM_E_FAIL
            elif ret == tss_lib.TPM_E_BAD_ORDINAL:
                raise TPM_E_BAD_ORDINAL
            elif ret == tss_lib.TPM_E_INSTALL_DISABLED:
                raise TPM_E_INSTALL_DISABLED
            elif ret == tss_lib.TPM_E_INVALID_KEYHANDLE:
                raise TPM_E_INVALID_KEYHANDLE
            elif ret == tss_lib.TPM_E_KEYNOTFOUND:
                raise TPM_E_KEYNOTFOUND
            elif ret == tss_lib.TPM_E_INAPPROPRIATE_ENC:
                raise TPM_E_INAPPROPRIATE_ENC
            elif ret == tss_lib.TPM_E_MIGRATEFAIL:
                raise TPM_E_MIGRATEFAIL
            elif ret == tss_lib.TPM_E_INVALID_PCR_INFO:
                raise TPM_E_INVALID_PCR_INFO
            elif ret == tss_lib.TPM_E_NOSPACE:
                raise TPM_E_NOSPACE
            elif ret == tss_lib.TPM_E_NOSRK:
                raise TPM_E_NOSRK
            elif ret == tss_lib.TPM_E_NOTSEALED_BLOB:
                raise TPM_E_NOTSEALED_BLOB
            elif ret == tss_lib.TPM_E_OWNER_SET:
                raise TPM_E_OWNER_SET
            elif ret == tss_lib.TPM_E_RESOURCES:
                raise TPM_E_RESOURCES
            elif ret == tss_lib.TPM_E_SHORTRANDOM:
                raise TPM_E_SHORTRANDOM
            elif ret == tss_lib.TPM_E_SIZE:
                raise TPM_E_SIZE
            elif ret == tss_lib.TPM_E_WRONGPCRVAL:
                raise TPM_E_WRONGPCRVAL
            elif ret == tss_lib.TPM_E_BAD_PARAM_SIZE:
                raise TPM_E_BAD_PARAM_SIZE
            elif ret == tss_lib.TPM_E_SHA_THREAD:
                raise TPM_E_SHA_THREAD
            elif ret == tss_lib.TPM_E_SHA_ERROR:
                raise TPM_E_SHA_ERROR
            elif ret == tss_lib.TPM_E_FAILEDSELFTEST:
                raise TPM_E_FAILEDSELFTEST
            elif ret == tss_lib.TPM_E_AUTH2FAIL:
                raise TPM_E_AUTH2FAIL
            elif ret == tss_lib.TPM_E_BADTAG:
                raise TPM_E_BADTAG
            elif ret == tss_lib.TPM_E_IOERROR:
                raise TPM_E_IOERROR
            elif ret == tss_lib.TPM_E_ENCRYPT_ERROR:
                raise TPM_E_ENCRYPT_ERROR
            elif ret == tss_lib.TPM_E_DECRYPT_ERROR:
                raise TPM_E_DECRYPT_ERROR
            elif ret == tss_lib.TPM_E_INVALID_AUTHHANDLE:
                raise TPM_E_INVALID_AUTHHANDLE
            elif ret == tss_lib.TPM_E_NO_ENDORSEMENT:
                raise TPM_E_NO_ENDORSEMENT
            elif ret == tss_lib.TPM_E_INVALID_KEYUSAGE:
                raise TPM_E_INVALID_KEYUSAGE
            elif ret == tss_lib.TPM_E_WRONG_ENTITYTYPE:
                raise TPM_E_WRONG_ENTITYTYPE
            elif ret == tss_lib.TPM_E_INVALID_POSTINIT:
                raise TPM_E_INVALID_POSTINIT
            elif ret == tss_lib.TPM_E_INAPPROPRIATE_SIG:
                raise TPM_E_INAPPROPRIATE_SIG
            elif ret == tss_lib.TPM_E_BAD_KEY_PROPERTY:
                raise TPM_E_BAD_KEY_PROPERTY
            elif ret == tss_lib.TPM_E_BAD_MIGRATION:
                raise TPM_E_BAD_MIGRATION
            elif ret == tss_lib.TPM_E_BAD_SCHEME:
                raise TPM_E_BAD_SCHEME
            elif ret == tss_lib.TPM_E_BAD_DATASIZE:
                raise TPM_E_BAD_DATASIZE
            elif ret == tss_lib.TPM_E_BAD_MODE:
                raise TPM_E_BAD_MODE
            elif ret == tss_lib.TPM_E_BAD_PRESENCE:
                raise TPM_E_BAD_PRESENCE
            elif ret == tss_lib.TPM_E_BAD_VERSION:
                raise TPM_E_BAD_VERSION
            elif ret == tss_lib.TPM_E_NO_WRAP_TRANSPORT:
                raise TPM_E_NO_WRAP_TRANSPORT
            elif ret == tss_lib.TPM_E_AUDITFAIL_UNSUCCESSFUL:
                raise TPM_E_AUDITFAIL_UNSUCCESSFUL
            elif ret == tss_lib.TPM_E_AUDITFAIL_SUCCESSFUL:
                raise TPM_E_AUDITFAIL_SUCCESSFUL
            elif ret == tss_lib.TPM_E_NOTRESETABLE:
                raise TPM_E_NOTRESETABLE
            elif ret == tss_lib.TPM_E_NOTLOCAL:
                raise TPM_E_NOTLOCAL
            elif ret == tss_lib.TPM_E_BAD_TYPE:
                raise TPM_E_BAD_TYPE
            elif ret == tss_lib.TPM_E_INVALID_RESOURCE:
                raise TPM_E_INVALID_RESOURCE
            elif ret == tss_lib.TPM_E_NOTFIPS:
                raise TPM_E_NOTFIPS
            elif ret == tss_lib.TPM_E_INVALID_FAMILY:
                raise TPM_E_INVALID_FAMILY
            elif ret == tss_lib.TPM_E_NO_NV_PERMISSION:
                raise TPM_E_NO_NV_PERMISSION
            elif ret == tss_lib.TPM_E_REQUIRES_SIGN:
                raise TPM_E_REQUIRES_SIGN
            elif ret == tss_lib.TPM_E_KEY_NOTSUPPORTED:
                raise TPM_E_KEY_NOTSUPPORTED
            elif ret == tss_lib.TPM_E_AUTH_CONFLICT:
                raise TPM_E_AUTH_CONFLICT
            elif ret == tss_lib.TPM_E_AREA_LOCKED:
                raise TPM_E_AREA_LOCKED
            elif ret == tss_lib.TPM_E_BAD_LOCALITY:
                raise TPM_E_BAD_LOCALITY
            elif ret == tss_lib.TPM_E_READ_ONLY:
                raise TPM_E_READ_ONLY
            elif ret == tss_lib.TPM_E_PER_NOWRITE:
                raise TPM_E_PER_NOWRITE
            elif ret == tss_lib.TPM_E_FAMILYCOUNT:
                raise TPM_E_FAMILYCOUNT
            elif ret == tss_lib.TPM_E_WRITE_LOCKED:
                raise TPM_E_WRITE_LOCKED
            elif ret == tss_lib.TPM_E_BAD_ATTRIBUTES:
                raise TPM_E_BAD_ATTRIBUTES
            elif ret == tss_lib.TPM_E_INVALID_STRUCTURE:
                raise TPM_E_INVALID_STRUCTURE
            elif ret == tss_lib.TPM_E_KEY_OWNER_CONTROL:
                raise TPM_E_KEY_OWNER_CONTROL
            elif ret == tss_lib.TPM_E_BAD_COUNTER:
                raise TPM_E_BAD_COUNTER
            elif ret == tss_lib.TPM_E_NOT_FULLWRITE:
                raise TPM_E_NOT_FULLWRITE
            elif ret == tss_lib.TPM_E_CONTEXT_GAP:
                raise TPM_E_CONTEXT_GAP
            elif ret == tss_lib.TPM_E_MAXNVWRITES:
                raise TPM_E_MAXNVWRITES
            elif ret == tss_lib.TPM_E_NOOPERATOR:
                raise TPM_E_NOOPERATOR
            elif ret == tss_lib.TPM_E_RESOURCEMISSING:
                raise TPM_E_RESOURCEMISSING
            elif ret == tss_lib.TPM_E_DELEGATE_LOCK:
                raise TPM_E_DELEGATE_LOCK
            elif ret == tss_lib.TPM_E_DELEGATE_FAMILY:
                raise TPM_E_DELEGATE_FAMILY
            elif ret == tss_lib.TPM_E_DELEGATE_ADMIN:
                raise TPM_E_DELEGATE_ADMIN
            elif ret == tss_lib.TPM_E_TRANSPORT_NOTEXCLUSIVE:
                raise TPM_E_TRANSPORT_NOTEXCLUSIVE
            elif ret == tss_lib.TPM_E_OWNER_CONTROL:
                raise TPM_E_OWNER_CONTROL
            elif ret == tss_lib.TPM_E_DAA_RESOURCES:
                raise TPM_E_DAA_RESOURCES
            elif ret == tss_lib.TPM_E_DAA_INPUT_DATA0:
                raise TPM_E_DAA_INPUT_DATA0
            elif ret == tss_lib.TPM_E_DAA_INPUT_DATA1:
                raise TPM_E_DAA_INPUT_DATA1
            elif ret == tss_lib.TPM_E_DAA_ISSUER_SETTINGS:
                raise TPM_E_DAA_ISSUER_SETTINGS
            elif ret == tss_lib.TPM_E_DAA_TPM_SETTINGS:
                raise TPM_E_DAA_TPM_SETTINGS
            elif ret == tss_lib.TPM_E_DAA_STAGE:
                raise TPM_E_DAA_STAGE
            elif ret == tss_lib.TPM_E_DAA_ISSUER_VALIDITY:
                raise TPM_E_DAA_ISSUER_VALIDITY
            elif ret == tss_lib.TPM_E_DAA_WRONG_W:
                raise TPM_E_DAA_WRONG_W
            elif ret == tss_lib.TPM_E_BAD_HANDLE:
                raise TPM_E_BAD_HANDLE
            elif ret == tss_lib.TPM_E_BAD_DELEGATE:
                raise TPM_E_BAD_DELEGATE
            elif ret == tss_lib.TPM_E_BADCONTEXT:
                raise TPM_E_BADCONTEXT
            elif ret == tss_lib.TPM_E_TOOMANYCONTEXTS:
                raise TPM_E_TOOMANYCONTEXTS
            elif ret == tss_lib.TPM_E_MA_TICKET_SIGNATURE:
                raise TPM_E_MA_TICKET_SIGNATURE
            elif ret == tss_lib.TPM_E_MA_DESTINATION:
                raise TPM_E_MA_DESTINATION
            elif ret == tss_lib.TPM_E_MA_SOURCE:
                raise TPM_E_MA_SOURCE
            elif ret == tss_lib.TPM_E_MA_AUTHORITY:
                raise TPM_E_MA_AUTHORITY
            elif ret == tss_lib.TPM_E_PERMANENTEK:
                raise TPM_E_PERMANENTEK
            elif ret == tss_lib.TPM_E_BAD_SIGNATURE:
                raise TPM_E_BAD_SIGNATURE
            elif ret == tss_lib.TPM_E_NOCONTEXTSPACE:
                raise TPM_E_NOCONTEXTSPACE
            elif ret == tss_lib.TPM_E_RETRY:
                raise TPM_E_RETRY
            elif ret == tss_lib.TPM_E_NEEDS_SELFTEST:
                raise TPM_E_NEEDS_SELFTEST
            elif ret == tss_lib.TPM_E_DOING_SELFTEST:
                raise TPM_E_DOING_SELFTEST
            elif ret == tss_lib.TPM_E_DEFEND_LOCK_RUNNING:
                raise TPM_E_DEFEND_LOCK_RUNNING
            else:
                raise TpmException("Unknown Error %x" % ret)
            
    return wrapper

tss_lib.Tspi_EncodeDER_TssBlob = wrap_libtspi_func(tss_lib.Tspi_EncodeDER_TssBlob)
tss_lib.Tspi_DecodeBER_TssBlob = wrap_libtspi_func(tss_lib.Tspi_DecodeBER_TssBlob)
tss_lib.Tspi_SetAttribUint32 = wrap_libtspi_func(tss_lib.Tspi_SetAttribUint32)
tss_lib.Tspi_GetAttribUint32 = wrap_libtspi_func(tss_lib.Tspi_GetAttribUint32)
tss_lib.Tspi_SetAttribData = wrap_libtspi_func(tss_lib.Tspi_SetAttribData)
tss_lib.Tspi_GetAttribData = wrap_libtspi_func(tss_lib.Tspi_GetAttribData)
tss_lib.Tspi_ChangeAuth = wrap_libtspi_func(tss_lib.Tspi_ChangeAuth)
tss_lib.Tspi_ChangeAuthAsym = wrap_libtspi_func(tss_lib.Tspi_ChangeAuthAsym)
tss_lib.Tspi_GetPolicyObject = wrap_libtspi_func(tss_lib.Tspi_GetPolicyObject)
tss_lib.Tspi_Context_Create = wrap_libtspi_func(tss_lib.Tspi_Context_Create)
tss_lib.Tspi_Context_Close = wrap_libtspi_func(tss_lib.Tspi_Context_Close)
tss_lib.Tspi_Context_Connect = wrap_libtspi_func(tss_lib.Tspi_Context_Connect)
tss_lib.Tspi_Context_FreeMemory = wrap_libtspi_func(tss_lib.Tspi_Context_FreeMemory)
tss_lib.Tspi_Context_GetDefaultPolicy = wrap_libtspi_func(tss_lib.Tspi_Context_GetDefaultPolicy)
tss_lib.Tspi_Context_CreateObject = wrap_libtspi_func(tss_lib.Tspi_Context_CreateObject)
tss_lib.Tspi_Context_CloseObject = wrap_libtspi_func(tss_lib.Tspi_Context_CloseObject)
tss_lib.Tspi_Context_GetCapability = wrap_libtspi_func(tss_lib.Tspi_Context_GetCapability)
tss_lib.Tspi_Context_GetTpmObject = wrap_libtspi_func(tss_lib.Tspi_Context_GetTpmObject)
tss_lib.Tspi_Context_SetTransEncryptionKey = wrap_libtspi_func(tss_lib.Tspi_Context_SetTransEncryptionKey)
tss_lib.Tspi_Context_CloseSignTransport = wrap_libtspi_func(tss_lib.Tspi_Context_CloseSignTransport)
tss_lib.Tspi_Context_LoadKeyByBlob = wrap_libtspi_func(tss_lib.Tspi_Context_LoadKeyByBlob)
tss_lib.Tspi_Context_LoadKeyByUUID = wrap_libtspi_func(tss_lib.Tspi_Context_LoadKeyByUUID)
tss_lib.Tspi_Context_RegisterKey = wrap_libtspi_func(tss_lib.Tspi_Context_RegisterKey)
tss_lib.Tspi_Context_UnregisterKey = wrap_libtspi_func(tss_lib.Tspi_Context_UnregisterKey)
tss_lib.Tspi_Context_GetKeyByUUID = wrap_libtspi_func(tss_lib.Tspi_Context_GetKeyByUUID)
tss_lib.Tspi_Context_GetKeyByPublicInfo = wrap_libtspi_func(tss_lib.Tspi_Context_GetKeyByPublicInfo)
tss_lib.Tspi_Context_GetRegisteredKeysByUUID = wrap_libtspi_func(tss_lib.Tspi_Context_GetRegisteredKeysByUUID)
tss_lib.Tspi_Context_GetRegisteredKeysByUUID2 = wrap_libtspi_func(tss_lib.Tspi_Context_GetRegisteredKeysByUUID2)
tss_lib.Tspi_Policy_SetSecret = wrap_libtspi_func(tss_lib.Tspi_Policy_SetSecret)
tss_lib.Tspi_Policy_FlushSecret = wrap_libtspi_func(tss_lib.Tspi_Policy_FlushSecret)
tss_lib.Tspi_Policy_AssignToObject = wrap_libtspi_func(tss_lib.Tspi_Policy_AssignToObject)
tss_lib.Tspi_TPM_KeyControlOwner = wrap_libtspi_func(tss_lib.Tspi_TPM_KeyControlOwner)
tss_lib.Tspi_TPM_CreateEndorsementKey = wrap_libtspi_func(tss_lib.Tspi_TPM_CreateEndorsementKey)
tss_lib.Tspi_TPM_CreateRevocableEndorsementKey = wrap_libtspi_func(tss_lib.Tspi_TPM_CreateRevocableEndorsementKey)
tss_lib.Tspi_TPM_RevokeEndorsementKey = wrap_libtspi_func(tss_lib.Tspi_TPM_RevokeEndorsementKey)
tss_lib.Tspi_TPM_GetPubEndorsementKey = wrap_libtspi_func(tss_lib.Tspi_TPM_GetPubEndorsementKey)
tss_lib.Tspi_TPM_OwnerGetSRKPubKey = wrap_libtspi_func(tss_lib.Tspi_TPM_OwnerGetSRKPubKey)
tss_lib.Tspi_TPM_TakeOwnership = wrap_libtspi_func(tss_lib.Tspi_TPM_TakeOwnership)
tss_lib.Tspi_TPM_ClearOwner = wrap_libtspi_func(tss_lib.Tspi_TPM_ClearOwner)
tss_lib.Tspi_TPM_CollateIdentityRequest = wrap_libtspi_func(tss_lib.Tspi_TPM_CollateIdentityRequest)
tss_lib.Tspi_TPM_ActivateIdentity = wrap_libtspi_func(tss_lib.Tspi_TPM_ActivateIdentity)
tss_lib.Tspi_TPM_CreateMaintenanceArchive = wrap_libtspi_func(tss_lib.Tspi_TPM_CreateMaintenanceArchive)
tss_lib.Tspi_TPM_KillMaintenanceFeature = wrap_libtspi_func(tss_lib.Tspi_TPM_KillMaintenanceFeature)
tss_lib.Tspi_TPM_LoadMaintenancePubKey = wrap_libtspi_func(tss_lib.Tspi_TPM_LoadMaintenancePubKey)
tss_lib.Tspi_TPM_CheckMaintenancePubKey = wrap_libtspi_func(tss_lib.Tspi_TPM_CheckMaintenancePubKey)
tss_lib.Tspi_TPM_SetOperatorAuth = wrap_libtspi_func(tss_lib.Tspi_TPM_SetOperatorAuth)
tss_lib.Tspi_TPM_SetStatus = wrap_libtspi_func(tss_lib.Tspi_TPM_SetStatus)
tss_lib.Tspi_TPM_GetStatus = wrap_libtspi_func(tss_lib.Tspi_TPM_GetStatus)
tss_lib.Tspi_TPM_GetCapability = wrap_libtspi_func(tss_lib.Tspi_TPM_GetCapability)
tss_lib.Tspi_TPM_GetCapabilitySigned = wrap_libtspi_func(tss_lib.Tspi_TPM_GetCapabilitySigned)
tss_lib.Tspi_TPM_SelfTestFull = wrap_libtspi_func(tss_lib.Tspi_TPM_SelfTestFull)
tss_lib.Tspi_TPM_CertifySelfTest = wrap_libtspi_func(tss_lib.Tspi_TPM_CertifySelfTest)
tss_lib.Tspi_TPM_GetTestResult = wrap_libtspi_func(tss_lib.Tspi_TPM_GetTestResult)
tss_lib.Tspi_TPM_GetRandom = wrap_libtspi_func(tss_lib.Tspi_TPM_GetRandom)
tss_lib.Tspi_TPM_StirRandom = wrap_libtspi_func(tss_lib.Tspi_TPM_StirRandom)
tss_lib.Tspi_TPM_GetEvent = wrap_libtspi_func(tss_lib.Tspi_TPM_GetEvent)
tss_lib.Tspi_TPM_GetEvents = wrap_libtspi_func(tss_lib.Tspi_TPM_GetEvents)
tss_lib.Tspi_TPM_GetEventLog = wrap_libtspi_func(tss_lib.Tspi_TPM_GetEventLog)
tss_lib.Tspi_TPM_Quote = wrap_libtspi_func(tss_lib.Tspi_TPM_Quote)
tss_lib.Tspi_TPM_Quote2 = wrap_libtspi_func(tss_lib.Tspi_TPM_Quote2)
tss_lib.Tspi_TPM_PcrExtend = wrap_libtspi_func(tss_lib.Tspi_TPM_PcrExtend)
tss_lib.Tspi_TPM_PcrRead = wrap_libtspi_func(tss_lib.Tspi_TPM_PcrRead)
tss_lib.Tspi_TPM_PcrReset = wrap_libtspi_func(tss_lib.Tspi_TPM_PcrReset)
tss_lib.Tspi_TPM_AuthorizeMigrationTicket = wrap_libtspi_func(tss_lib.Tspi_TPM_AuthorizeMigrationTicket)
tss_lib.Tspi_TPM_CMKSetRestrictions = wrap_libtspi_func(tss_lib.Tspi_TPM_CMKSetRestrictions)
tss_lib.Tspi_TPM_CMKApproveMA = wrap_libtspi_func(tss_lib.Tspi_TPM_CMKApproveMA)
tss_lib.Tspi_TPM_CMKCreateTicket = wrap_libtspi_func(tss_lib.Tspi_TPM_CMKCreateTicket)
tss_lib.Tspi_TPM_ReadCounter = wrap_libtspi_func(tss_lib.Tspi_TPM_ReadCounter)
tss_lib.Tspi_TPM_ReadCurrentTicks = wrap_libtspi_func(tss_lib.Tspi_TPM_ReadCurrentTicks)
tss_lib.Tspi_TPM_DirWrite = wrap_libtspi_func(tss_lib.Tspi_TPM_DirWrite)
tss_lib.Tspi_TPM_DirRead = wrap_libtspi_func(tss_lib.Tspi_TPM_DirRead)
tss_lib.Tspi_TPM_Delegate_AddFamily = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_AddFamily)
tss_lib.Tspi_TPM_Delegate_GetFamily = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_GetFamily)
tss_lib.Tspi_TPM_Delegate_InvalidateFamily = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_InvalidateFamily)
tss_lib.Tspi_TPM_Delegate_CreateDelegation = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_CreateDelegation)
tss_lib.Tspi_TPM_Delegate_CacheOwnerDelegation = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_CacheOwnerDelegation)
tss_lib.Tspi_TPM_Delegate_UpdateVerificationCount = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_UpdateVerificationCount)
tss_lib.Tspi_TPM_Delegate_VerifyDelegation = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_VerifyDelegation)
tss_lib.Tspi_TPM_Delegate_ReadTables = wrap_libtspi_func(tss_lib.Tspi_TPM_Delegate_ReadTables)
tss_lib.Tspi_TPM_GetAuditDigest = wrap_libtspi_func(tss_lib.Tspi_TPM_GetAuditDigest)
tss_lib.Tspi_PcrComposite_SelectPcrIndex = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_SelectPcrIndex)
tss_lib.Tspi_PcrComposite_SelectPcrIndexEx = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_SelectPcrIndexEx)
tss_lib.Tspi_PcrComposite_SetPcrValue = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_SetPcrValue)
tss_lib.Tspi_PcrComposite_GetPcrValue = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_GetPcrValue)
tss_lib.Tspi_PcrComposite_SetPcrLocality = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_SetPcrLocality)
tss_lib.Tspi_PcrComposite_GetPcrLocality = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_GetPcrLocality)
tss_lib.Tspi_PcrComposite_GetCompositeHash = wrap_libtspi_func(tss_lib.Tspi_PcrComposite_GetCompositeHash)
tss_lib.Tspi_Key_LoadKey = wrap_libtspi_func(tss_lib.Tspi_Key_LoadKey)
tss_lib.Tspi_Key_UnloadKey = wrap_libtspi_func(tss_lib.Tspi_Key_UnloadKey)
tss_lib.Tspi_Key_GetPubKey = wrap_libtspi_func(tss_lib.Tspi_Key_GetPubKey)
tss_lib.Tspi_Key_CertifyKey = wrap_libtspi_func(tss_lib.Tspi_Key_CertifyKey)
tss_lib.Tspi_Key_CreateKey = wrap_libtspi_func(tss_lib.Tspi_Key_CreateKey)
tss_lib.Tspi_Key_WrapKey = wrap_libtspi_func(tss_lib.Tspi_Key_WrapKey)
tss_lib.Tspi_Key_CreateMigrationBlob = wrap_libtspi_func(tss_lib.Tspi_Key_CreateMigrationBlob)
tss_lib.Tspi_Key_ConvertMigrationBlob = wrap_libtspi_func(tss_lib.Tspi_Key_ConvertMigrationBlob)
tss_lib.Tspi_Key_CMKCreateBlob = wrap_libtspi_func(tss_lib.Tspi_Key_CMKCreateBlob)
tss_lib.Tspi_Key_CMKConvertMigration = wrap_libtspi_func(tss_lib.Tspi_Key_CMKConvertMigration)
tss_lib.Tspi_Hash_Sign = wrap_libtspi_func(tss_lib.Tspi_Hash_Sign)
tss_lib.Tspi_Hash_VerifySignature = wrap_libtspi_func(tss_lib.Tspi_Hash_VerifySignature)
tss_lib.Tspi_Hash_SetHashValue = wrap_libtspi_func(tss_lib.Tspi_Hash_SetHashValue)
tss_lib.Tspi_Hash_GetHashValue = wrap_libtspi_func(tss_lib.Tspi_Hash_GetHashValue)
tss_lib.Tspi_Hash_UpdateHashValue = wrap_libtspi_func(tss_lib.Tspi_Hash_UpdateHashValue)
tss_lib.Tspi_Hash_TickStampBlob = wrap_libtspi_func(tss_lib.Tspi_Hash_TickStampBlob)
tss_lib.Tspi_Data_Bind = wrap_libtspi_func(tss_lib.Tspi_Data_Bind)
tss_lib.Tspi_Data_Unbind = wrap_libtspi_func(tss_lib.Tspi_Data_Unbind)
tss_lib.Tspi_Data_Seal = wrap_libtspi_func(tss_lib.Tspi_Data_Seal)
tss_lib.Tspi_Data_Unseal = wrap_libtspi_func(tss_lib.Tspi_Data_Unseal)
tss_lib.Tspi_NV_DefineSpace = wrap_libtspi_func(tss_lib.Tspi_NV_DefineSpace)
tss_lib.Tspi_NV_ReleaseSpace = wrap_libtspi_func(tss_lib.Tspi_NV_ReleaseSpace)
tss_lib.Tspi_NV_WriteValue = wrap_libtspi_func(tss_lib.Tspi_NV_WriteValue)
tss_lib.Tspi_NV_ReadValue = wrap_libtspi_func(tss_lib.Tspi_NV_ReadValue)
