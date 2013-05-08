typedef uint8_t            BYTE;
typedef int8_t             TSS_BOOL;
typedef uint16_t           UINT16;
typedef uint32_t           UINT32;
typedef uint64_t           UINT64;

typedef uint16_t           TSS_UNICODE;
typedef void*              PVOID;
typedef UINT32 TSS_RESULT;
typedef UINT32 TSS_HANDLE;
typedef UINT32 TSS_FLAG;
typedef UINT32 TSS_HOBJECT;
typedef TSS_HOBJECT TSS_HCONTEXT;
typedef TSS_HOBJECT TSS_HPOLICY;
typedef TSS_HOBJECT TSS_HTPM;
typedef TSS_HOBJECT TSS_HKEY;
typedef TSS_HOBJECT TSS_HENCDATA;
typedef TSS_HOBJECT TSS_HPCRS;
typedef TSS_HOBJECT TSS_HHASH;
typedef TSS_HOBJECT TSS_HNVSTORE;
typedef TSS_HOBJECT TSS_HMIGDATA;
typedef TSS_HOBJECT TSS_HDELFAMILY;
typedef TSS_HOBJECT TSS_HDAA_CREDENTIAL;
typedef TSS_HOBJECT TSS_HDAA_ISSUER_KEY;
typedef TSS_HOBJECT TSS_HDAA_ARA_KEY;
typedef UINT32 TSS_EVENTTYPE;
typedef UINT16 TSS_MIGRATE_SCHEME;
typedef UINT32 TSS_ALGORITHM_ID;
typedef UINT32 TSS_KEY_USAGE_ID;
typedef UINT16 TSS_KEY_ENC_SCHEME;
typedef UINT16 TSS_KEY_SIG_SCHEME;
typedef BYTE TSS_KEY_AUTH_DATA_USAGE;
typedef UINT32 TSS_CMK_DELEGATE;
typedef UINT32 TSS_NV_INDEX;
typedef UINT32 TSS_COUNTER_ID;
typedef BYTE TPM_BOOL;
typedef BYTE TPM_LOCALITY_MODIFIER;
typedef UINT32 TPM_COMMAND_CODE;
typedef UINT32 TPM_COUNT_ID;
typedef UINT32 TPM_REDIT_COMMAND;
typedef UINT32 TPM_HANDLE;
typedef UINT32 TPM_AUTHHANDLE;
typedef UINT32 TPM_TRANSHANDLE;
typedef UINT32 TPM_KEYHANDLE;
typedef UINT32 TPM_DIRINDEX;
typedef UINT32 TPM_PCRINDEX;
typedef UINT32 TPM_RESULT;
typedef UINT32 TPM_MODIFIER_INDICATOR;
typedef UINT16 TPM_STRUCTURE_TAG;
typedef UINT32 TPM_RESOURCE_TYPE;
typedef BYTE TPM_PAYLOAD_TYPE;
typedef UINT16 TPM_ENTITY_TYPE;
typedef UINT32 TPM_KEY_HANDLE;
typedef UINT16 TPM_STARTUP_TYPE;
typedef UINT16 TPM_PROTOCOL_ID;
typedef UINT32 TPM_ALGORITHM_ID;
typedef UINT16 TPM_PHYSICAL_PRESENCE;
typedef UINT16 TPM_MIGRATE_SCHEME;
typedef UINT16 TPM_EK_TYPE;
typedef UINT16 TPM_PLATFORM_SPECIFIC;

typedef struct tdTPM_STRUCT_VER
{
    BYTE major;
    BYTE minor;
    BYTE revMajor;
    BYTE revMinor;
} TPM_STRUCT_VER;

typedef struct tdTPM_VERSION_BYTE
{

    int leastSigVer : 4;
    int mostSigVer : 4;
} TPM_VERSION_BYTE;

typedef struct tdTPM_VERSION
{
    BYTE major;
    BYTE minor;
    BYTE revMajor;
    BYTE revMinor;
} TPM_VERSION;

typedef struct tdTPM_DIGEST
{
    BYTE digest[0x14];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_CHOSENID_HASH;
typedef TPM_DIGEST TPM_COMPOSITE_HASH;
typedef TPM_DIGEST TPM_DIRVALUE;
typedef TPM_DIGEST TPM_HMAC;
typedef TPM_DIGEST TPM_PCRVALUE;
typedef TPM_DIGEST TPM_AUDITDIGEST;

typedef struct tdTPM_NONCE
{
    BYTE nonce[0x14];
} TPM_NONCE;

typedef TPM_NONCE TPM_DAA_TPM_SEED;
typedef TPM_NONCE TPM_DAA_CONTEXT_SEED;

typedef struct tdTPM_AUTHDATA
{
    BYTE authdata[0x14];
} TPM_AUTHDATA;

typedef TPM_AUTHDATA TPM_SECRET;
typedef TPM_AUTHDATA TPM_ENCAUTH;

typedef struct tdTPM_KEY_HANDLE_LIST
{
    UINT16 loaded;
   
        TPM_KEY_HANDLE *handle;
} TPM_KEY_HANDLE_LIST;


typedef UINT16 TPM_KEY_USAGE;
typedef UINT16 TPM_SIG_SCHEME;
typedef UINT16 TPM_ENC_SCHEME;
typedef BYTE TPM_AUTH_DATA_USAGE;
typedef UINT32 TPM_KEY_FLAGS;
typedef struct tdTPM_CHANGEAUTH_VALIDATE
{
    TPM_SECRET newAuthSecret;
    TPM_NONCE n1;
} TPM_CHANGEAUTH_VALIDATE;
typedef UINT32 TPM_ACTUAL_COUNT;
typedef struct tdTPM_COUNTER_VALUE
{
    TPM_STRUCTURE_TAG tag;
    BYTE label[4];
    TPM_ACTUAL_COUNT counter;
} TPM_COUNTER_VALUE;



typedef struct tdTPM_SIGN_INFO
{
    TPM_STRUCTURE_TAG tag;
    BYTE fixed[4];
    TPM_NONCE replay;
    UINT32 dataLen;
   
        BYTE *data;
} TPM_SIGN_INFO;




typedef struct tdTPM_MSA_COMPOSITE
{
    UINT32 MSAlist;
   
        TPM_DIGEST *migAuthDigest;
} TPM_MSA_COMPOSITE;




typedef struct tdTPM_CMK_AUTH
{
    TPM_DIGEST migrationAuthorityDigest;
    TPM_DIGEST destinationKeyDigest;
    TPM_DIGEST sourceKeyDigest;
} TPM_CMK_AUTH;




typedef UINT32 TPM_CMK_DELEGATE;
typedef struct tdTPM_SELECT_SIZE
{
    BYTE major;
    BYTE minor;
    UINT16 reqSize;
} TPM_SELECT_SIZE;




typedef struct tdTPM_CMK_MIGAUTH
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST msaDigest;
    TPM_DIGEST pubKeyDigest;
} TPM_CMK_MIGAUTH;




typedef struct tdTPM_CMK_SIGTICKET
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST verKeyDigest;
    TPM_DIGEST signedData;
} TPM_CMK_SIGTICKET;




typedef struct tdTPM_CMK_MA_APPROVAL
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST migrationAuthorityDigest;
} TPM_CMK_MA_APPROVAL;





typedef UINT16 TPM_TAG;
typedef struct tdTPM_PERMANENT_FLAGS
{
    TPM_STRUCTURE_TAG tag;
    TSS_BOOL disable;
    TSS_BOOL ownership;
    TSS_BOOL deactivated;
    TSS_BOOL readPubek;
    TSS_BOOL disableOwnerClear;
    TSS_BOOL allowMaintenance;
    TSS_BOOL physicalPresenceLifetimeLock;
    TSS_BOOL physicalPresenceHWEnable;
    TSS_BOOL physicalPresenceCMDEnable;
    TSS_BOOL CEKPUsed;
    TSS_BOOL TPMpost;
    TSS_BOOL TPMpostLock;
    TSS_BOOL FIPS;
    TSS_BOOL Operator;
    TSS_BOOL enableRevokeEK;
    TSS_BOOL nvLocked;
    TSS_BOOL readSRKPub;
    TSS_BOOL tpmEstablished;
    TSS_BOOL maintenanceDone;
    TSS_BOOL disableFullDALogicInfo;
} TPM_PERMANENT_FLAGS;
typedef struct tdTPM_STCLEAR_FLAGS
{
    TPM_STRUCTURE_TAG tag;
    TSS_BOOL deactivated;
    TSS_BOOL disableForceClear;
    TSS_BOOL physicalPresence;
    TSS_BOOL physicalPresenceLock;
    TSS_BOOL bGlobalLock;
} TPM_STCLEAR_FLAGS;
typedef struct tdTPM_STANY_FLAGS
{
    TPM_STRUCTURE_TAG tag;
    TSS_BOOL postInitialise;
    TPM_MODIFIER_INDICATOR localityModifier;
    TSS_BOOL transportExclusive;
    TSS_BOOL TOSPresent;
} TPM_STANY_FLAGS;
typedef BYTE TPM_LOCALITY_SELECTION;






typedef struct tdTPM_PCR_SELECTION
{
    UINT16 sizeOfSelect;
   
        BYTE *pcrSelect;
} TPM_PCR_SELECTION;

typedef struct tdTPM_PCR_COMPOSITE
{
    TPM_PCR_SELECTION select;
    UINT32 valueSize;
   
        TPM_PCRVALUE *pcrValue;
} TPM_PCR_COMPOSITE;

typedef struct tdTPM_PCR_INFO
{
    TPM_PCR_SELECTION pcrSelection;
    TPM_COMPOSITE_HASH digestAtRelease;
    TPM_COMPOSITE_HASH digestAtCreation;
} TPM_PCR_INFO;

typedef struct tdTPM_PCR_INFO_LONG
{
    TPM_STRUCTURE_TAG tag;
    TPM_LOCALITY_SELECTION localityAtCreation;
    TPM_LOCALITY_SELECTION localityAtRelease;
    TPM_PCR_SELECTION creationPCRSelection;
    TPM_PCR_SELECTION releasePCRSelection;
    TPM_COMPOSITE_HASH digestAtCreation;
    TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO_LONG;

typedef struct tdTPM_PCR_INFO_SHORT
{
    TPM_PCR_SELECTION pcrSelection;
    TPM_LOCALITY_SELECTION localityAtRelease;
    TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO_SHORT;

typedef struct tdTPM_PCR_ATTRIBUTES
{
    BYTE pcrReset;
    TPM_LOCALITY_SELECTION pcrExtendLocal;
    TPM_LOCALITY_SELECTION pcrResetLocal;
} TPM_PCR_ATTRIBUTES;






typedef struct tdTPM_STORED_DATA
{
    TPM_STRUCT_VER ver;
    UINT32 sealInfoSize;
   
        BYTE *sealInfo;
    UINT32 encDataSize;
   
        BYTE *encData;
} TPM_STORED_DATA;

typedef struct tdTPM_STORED_DATA12
{
    TPM_STRUCTURE_TAG tag;
    TPM_ENTITY_TYPE et;
    UINT32 sealInfoSize;
   
        BYTE *sealInfo;
    UINT32 encDataSize;
   
        BYTE *encData;
} TPM_STORED_DATA12;

typedef struct tdTPM_SEALED_DATA
{
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET authData;
    TPM_NONCE tpmProof;
    TPM_DIGEST storedDigest;
    UINT32 dataSize;
   
        BYTE *data;
} TPM_SEALED_DATA;

typedef struct tdTPM_SYMMETRIC_KEY
{
    TPM_ALGORITHM_ID algId;
    TPM_ENC_SCHEME encScheme;
    UINT16 size;
   
        BYTE *data;
} TPM_SYMMETRIC_KEY;

typedef struct tdTPM_BOUND_DATA
{
    TPM_STRUCT_VER ver;
    TPM_PAYLOAD_TYPE payload;
    BYTE *payloadData;
} TPM_BOUND_DATA;





typedef struct tdTPM_KEY_PARMS
{
    TPM_ALGORITHM_ID algorithmID;
    TPM_ENC_SCHEME encScheme;
    TPM_SIG_SCHEME sigScheme;
    UINT32 parmSize;
   
        BYTE *parms;
} TPM_KEY_PARMS;

typedef struct tdTPM_RSA_KEY_PARMS
{
    UINT32 keyLength;
    UINT32 numPrimes;
    UINT32 exponentSize;
   
        BYTE *exponent;
} TPM_RSA_KEY_PARMS;

typedef struct tdTPM_SYMMETRIC_KEY_PARMS
{
    UINT32 keyLength;
    UINT32 blockSize;
    UINT32 ivSize;
   
        BYTE *IV;
} TPM_SYMMETRIC_KEY_PARMS;

typedef struct tdTPM_STORE_PUBKEY
{
    UINT32 keyLength;
   
        BYTE *key;
} TPM_STORE_PUBKEY;

typedef struct tdTPM_PUBKEY
{
    TPM_KEY_PARMS algorithmParms;
    TPM_STORE_PUBKEY pubKey;
} TPM_PUBKEY;

typedef struct tdTPM_STORE_PRIVKEY
{
    UINT32 keyLength;
   
        BYTE *key;
} TPM_STORE_PRIVKEY;

typedef struct tdTPM_STORE_ASYMKEY
{
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET usageAuth;
    TPM_SECRET migrationAuth;
    TPM_DIGEST pubDataDigest;
    TPM_STORE_PRIVKEY privKey;
} TPM_STORE_ASYMKEY;

typedef struct tdTPM_KEY
{
    TPM_STRUCT_VER ver;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    UINT32 PCRInfoSize;
   
        BYTE *PCRInfo;
    TPM_STORE_PUBKEY pubKey;
    UINT32 encSize;
   
        BYTE *encData;
} TPM_KEY;

typedef struct tdTPM_KEY12
{
    TPM_STRUCTURE_TAG tag;
    UINT16 fill;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    UINT32 PCRInfoSize;
   
       BYTE *PCRInfo;
    TPM_STORE_PUBKEY pubKey;
    UINT32 encSize;
   
       BYTE *encData;
} TPM_KEY12;

typedef struct tdTPM_MIGRATE_ASYMKEY
{
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET usageAuth;
    TPM_DIGEST pubDataDigest;
    UINT32 partPrivKeyLen;
   
        BYTE *partPrivKey;
} TPM_MIGRATE_ASYMKEY;


typedef UINT32 TPM_KEY_CONTROL;






typedef struct tdTPM_MIGRATIONKEYAUTH
{
    TPM_PUBKEY migrationKey;
    TPM_MIGRATE_SCHEME migrationScheme;
    TPM_DIGEST digest;
} TPM_MIGRATIONKEYAUTH;





typedef struct tdTPM_CERTIFY_INFO
{
    TPM_STRUCT_VER version;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    TPM_DIGEST pubkeyDigest;
    TPM_NONCE data;
    TPM_BOOL parentPCRStatus;
    UINT32 PCRInfoSize;
   
        BYTE *PCRInfo;
} TPM_CERTIFY_INFO;

typedef struct tdTPM_CERTIFY_INFO2
{
    TPM_STRUCTURE_TAG tag;
    BYTE fill;
    TPM_PAYLOAD_TYPE payloadType;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    TPM_DIGEST pubkeyDigest;
    TPM_NONCE data;
    TPM_BOOL parentPCRStatus;
    UINT32 PCRInfoSize;
   
        BYTE *PCRInfo;
    UINT32 migrationAuthoritySize;
   
        BYTE *migrationAuthority;
} TPM_CERTIFY_INFO2;

typedef struct tdTPM_QUOTE_INFO
{
    TPM_STRUCT_VER version;
    BYTE fixed[4];
    TPM_COMPOSITE_HASH compositeHash;
    TPM_NONCE externalData;
} TPM_QUOTE_INFO;

typedef struct tdTPM_QUOTE_INFO2
{
    TPM_STRUCTURE_TAG tag;
    BYTE fixed[4];
    TPM_NONCE externalData;
    TPM_PCR_INFO_SHORT infoShort;
} TPM_QUOTE_INFO2;







typedef struct tdTPM_EK_BLOB
{
    TPM_STRUCTURE_TAG tag;
    TPM_EK_TYPE ekType;
    UINT32 blobSize;
   
        BYTE *blob;
} TPM_EK_BLOB;

typedef struct tdTPM_EK_BLOB_ACTIVATE
{
    TPM_STRUCTURE_TAG tag;
    TPM_SYMMETRIC_KEY sessionKey;
    TPM_DIGEST idDigest;
    TPM_PCR_INFO_SHORT pcrInfo;
} TPM_EK_BLOB_ACTIVATE;

typedef struct tdTPM_EK_BLOB_AUTH
{
    TPM_STRUCTURE_TAG tag;
    TPM_SECRET authValue;
} TPM_EK_BLOB_AUTH;


typedef struct tdTPM_IDENTITY_CONTENTS
{
    TPM_STRUCT_VER ver;
    UINT32 ordinal;
    TPM_CHOSENID_HASH labelPrivCADigest;
    TPM_PUBKEY identityPubKey;
} TPM_IDENTITY_CONTENTS;

typedef struct tdTPM_IDENTITY_REQ
{
    UINT32 asymSize;
    UINT32 symSize;
    TPM_KEY_PARMS asymAlgorithm;
    TPM_KEY_PARMS symAlgorithm;
   
        BYTE *asymBlob;
   
        BYTE *symBlob;
} TPM_IDENTITY_REQ;

typedef struct tdTPM_IDENTITY_PROOF
{
    TPM_STRUCT_VER ver;
    UINT32 labelSize;
    UINT32 identityBindingSize;
    UINT32 endorsementSize;
    UINT32 platformSize;
    UINT32 conformanceSize;
    TPM_PUBKEY identityKey;
   
      BYTE *labelArea;
   
      BYTE *identityBinding;
   
      BYTE *endorsementCredential;
   
      BYTE *platformCredential;
   
      BYTE *conformanceCredential;
} TPM_IDENTITY_PROOF;

typedef struct tdTPM_ASYM_CA_CONTENTS
{
    TPM_SYMMETRIC_KEY sessionKey;
    TPM_DIGEST idDigest;
} TPM_ASYM_CA_CONTENTS;

typedef struct tdTPM_SYM_CA_ATTESTATION
{
    UINT32 credSize;
    TPM_KEY_PARMS algorithm;
   
        BYTE *credential;
} TPM_SYM_CA_ATTESTATION;







typedef struct tdTPM_CURRENT_TICKS
{
    TPM_STRUCTURE_TAG tag;
    UINT64 currentTicks;
    UINT16 tickRate;
    TPM_NONCE tickNonce;
} TPM_CURRENT_TICKS;






typedef UINT32 TPM_TRANSPORT_ATTRIBUTES;




typedef struct tdTPM_TRANSPORT_PUBLIC
{
    TPM_STRUCTURE_TAG tag;
    TPM_TRANSPORT_ATTRIBUTES transAttributes;
    TPM_ALGORITHM_ID algId;
    TPM_ENC_SCHEME encScheme;
} TPM_TRANSPORT_PUBLIC;

typedef struct tdTPM_TRANSPORT_INTERNAL
{
    TPM_STRUCTURE_TAG tag;
    TPM_AUTHDATA authData;
    TPM_TRANSPORT_PUBLIC transPublic;
    TPM_TRANSHANDLE transHandle;
    TPM_NONCE transNonceEven;
    TPM_DIGEST transDigest;
} TPM_TRANSPORT_INTERNAL;

typedef struct tdTPM_TRANSPORT_LOG_IN
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST parameters;
    TPM_DIGEST pubKeyHash;
} TPM_TRANSPORT_LOG_IN;

typedef struct tdTPM_TRANSPORT_LOG_OUT
{
    TPM_STRUCTURE_TAG tag;
    TPM_CURRENT_TICKS currentTicks;
    TPM_DIGEST parameters;
    TPM_MODIFIER_INDICATOR locality;
} TPM_TRANSPORT_LOG_OUT;

typedef struct tdTPM_TRANSPORT_AUTH
{
    TPM_STRUCTURE_TAG tag;
    TPM_AUTHDATA authData;
} TPM_TRANSPORT_AUTH;






typedef struct tdTPM_AUDIT_EVENT_IN
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST inputParms;
    TPM_COUNTER_VALUE auditCount;
} TPM_AUDIT_EVENT_IN;

typedef struct tdTPM_AUDIT_EVENT_OUT
{
    TPM_STRUCTURE_TAG tag;
    TPM_COMMAND_CODE ordinal;
    TPM_DIGEST outputParms;
    TPM_COUNTER_VALUE auditCount;
    TPM_RESULT returnCode;
} TPM_AUDIT_EVENT_OUT;















typedef struct tdTPM_CONTEXT_BLOB
{
    TPM_STRUCTURE_TAG tag;
    TPM_RESOURCE_TYPE resourceType;
    TPM_HANDLE handle;
    BYTE label[16];
    UINT32 contextCount;
    TPM_DIGEST integrityDigest;
    UINT32 additionalSize;
   
        BYTE *additionalData;
    UINT32 sensitiveSize;
   
        BYTE *sensitiveData;
} TPM_CONTEXT_BLOB;

typedef struct tdTPM_CONTEXT_SENSITIVE
{
    TPM_STRUCTURE_TAG tag;
    TPM_NONCE contextNonce;
    UINT32 internalSize;
   
        BYTE *internalData;
} TPM_CONTEXT_SENSITIVE;




typedef UINT32 TPM_NV_INDEX;
typedef UINT32 TPM_NV_PER_ATTRIBUTES;
typedef struct tdTPM_NV_ATTRIBUTES
{
    TPM_STRUCTURE_TAG tag;
    TPM_NV_PER_ATTRIBUTES attributes;
} TPM_NV_ATTRIBUTES;


typedef struct tdTPM_NV_DATA_PUBLIC
{
    TPM_STRUCTURE_TAG tag;
    TPM_NV_INDEX nvIndex;
    TPM_PCR_INFO_SHORT pcrInfoRead;
    TPM_PCR_INFO_SHORT pcrInfoWrite;
    TPM_NV_ATTRIBUTES permission;
    TPM_BOOL bReadSTClear;
    TPM_BOOL bWriteSTClear;
    TPM_BOOL bWriteDefine;
    UINT32 dataSize;
} TPM_NV_DATA_PUBLIC;
typedef UINT32 TPM_FAMILY_VERIFICATION;

typedef UINT32 TPM_FAMILY_ID;

typedef UINT32 TPM_DELEGATE_INDEX;

typedef UINT32 TPM_FAMILY_OPERATION;





typedef UINT32 TPM_FAMILY_FLAGS;



typedef struct tdTPM_FAMILY_LABEL
{
    BYTE label;
} TPM_FAMILY_LABEL;

typedef struct tdTPM_FAMILY_TABLE_ENTRY
{
    TPM_STRUCTURE_TAG tag;
    TPM_FAMILY_LABEL label;
    TPM_FAMILY_ID familyID;
    TPM_FAMILY_VERIFICATION verificationCount;
    TPM_FAMILY_FLAGS flags;
} TPM_FAMILY_TABLE_ENTRY;
typedef struct tdTPM_DELEGATE_LABEL
{
    BYTE label;
} TPM_DELEGATE_LABEL;


typedef UINT32 TPM_DELEGATE_TYPE;



typedef struct tdTPM_DELEGATIONS
{
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_TYPE delegateType;
    UINT32 per1;
    UINT32 per2;
} TPM_DELEGATIONS;

typedef struct tdTPM_DELEGATE_PUBLIC
{
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_LABEL label;
    TPM_PCR_INFO_SHORT pcrInfo;
    TPM_DELEGATIONS permissions;
    TPM_FAMILY_ID familyID;
    TPM_FAMILY_VERIFICATION verificationCount;
} TPM_DELEGATE_PUBLIC;

typedef struct tdTPM_DELEGATE_TABLE_ROW
{
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_SECRET authValue;
} TPM_DELEGATE_TABLE_ROW;
typedef struct tdTPM_DELEGATE_SENSITIVE
{
    TPM_STRUCTURE_TAG tag;
    TPM_SECRET authValue;
} TPM_DELEGATE_SENSITIVE;

typedef struct tdTPM_DELEGATE_OWNER_BLOB
{
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_DIGEST integrityDigest;
    UINT32 additionalSize;
   
        BYTE *additionalArea;
    UINT32 sensitiveSize;
   
        BYTE *sensitiveArea;
} TPM_DELEGATE_OWNER_BLOB;

typedef struct tdTPM_DELEGATE_KEY_BLOB
{
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_DIGEST integrityDigest;
    TPM_DIGEST pubKeyDigest;
    UINT32 additionalSize;
   
        BYTE *additionalArea;
    UINT32 sensitiveSize;
   
        BYTE *sensitiveArea;
} TPM_DELEGATE_KEY_BLOB;





typedef UINT32 TPM_CAPABILITY_AREA;
typedef struct tdTPM_CAP_VERSION_INFO
{
    TPM_STRUCTURE_TAG tag;
    TPM_VERSION version;
    UINT16 specLevel;
    BYTE errataRev;
    BYTE tpmVendorID[4];
    UINT16 vendorSpecificSize;
   
        BYTE *vendorSpecific;
} TPM_CAP_VERSION_INFO;




typedef BYTE TPM_DA_STATE;




typedef struct tdTPM_DA_ACTION_TYPE
{
    TPM_STRUCTURE_TAG tag;
    UINT32 actions;
} TPM_DA_ACTION_TYPE;






typedef struct tdTPM_DA_INFO
{
    TPM_STRUCTURE_TAG tag;
    TPM_DA_STATE state;
    UINT16 currentCount;
    UINT16 threshholdCount;
    TPM_DA_ACTION_TYPE actionAtThreshold;
    UINT32 actionDependValue;
    UINT32 vendorDataSize;
   
        BYTE *vendorData;
} TPM_DA_INFO;


typedef struct tdTPM_DA_INFO_LIMITED
{
    TPM_STRUCTURE_TAG tag;
    TPM_DA_STATE state;
    TPM_DA_ACTION_TYPE actionAtThreshold;
    UINT32 vendorDataSize;
   
        BYTE *vendorData;
} TPM_DA_INFO_LIMITED;
typedef struct tdTPM_DAA_ISSUER
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digest_R0;
    TPM_DIGEST DAA_digest_R1;
    TPM_DIGEST DAA_digest_S0;
    TPM_DIGEST DAA_digest_S1;
    TPM_DIGEST DAA_digest_n;
    TPM_DIGEST DAA_digest_gamma;
    BYTE DAA_generic_q[26];
} TPM_DAA_ISSUER;


typedef struct tdTPM_DAA_TPM
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digestIssuer;
    TPM_DIGEST DAA_digest_v0;
    TPM_DIGEST DAA_digest_v1;
    TPM_DIGEST DAA_rekey;
    UINT32 DAA_count;
} TPM_DAA_TPM;

typedef struct tdTPM_DAA_CONTEXT
{
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digestContext;
    TPM_DIGEST DAA_digest;
    TPM_DAA_CONTEXT_SEED DAA_contextSeed;
    BYTE DAA_scratch[256];
    BYTE DAA_stage;
} TPM_DAA_CONTEXT;

typedef struct tdTPM_DAA_JOINDATA
{
    BYTE DAA_join_u0[128];
    BYTE DAA_join_u1[138];
    TPM_DIGEST DAA_digest_n0;
} TPM_DAA_JOINDATA;

typedef struct tdTPM_DAA_BLOB
{
    TPM_STRUCTURE_TAG tag;
    TPM_RESOURCE_TYPE resourceType;
    BYTE label[16];
    TPM_DIGEST blobIntegrity;
    UINT32 additionalSize;
   
        BYTE *additionalData;
    UINT32 sensitiveSize;
   
        BYTE *sensitiveData;
} TPM_DAA_BLOB;

typedef struct tdTPM_DAA_SENSITIVE
{
    TPM_STRUCTURE_TAG tag;
    UINT32 internalSize;
   
        BYTE *internalData;
} TPM_DAA_SENSITIVE;
typedef UINT32 TPM_SYM_MODE;

typedef struct tdTSS_VERSION
{
    BYTE bMajor;
    BYTE bMinor;
    BYTE bRevMajor;
    BYTE bRevMinor;
} TSS_VERSION;

typedef struct tdTSS_PCR_EVENT
{
    TSS_VERSION versionInfo;
    UINT32 ulPcrIndex;
    TSS_EVENTTYPE eventType;
    UINT32 ulPcrValueLength;



    BYTE* rgbPcrValue;
    UINT32 ulEventLength;



    BYTE* rgbEvent;
} TSS_PCR_EVENT;


typedef struct tdTSS_EVENT_CERT
{
    TSS_VERSION versionInfo;
    UINT32 ulCertificateHashLength;



    BYTE* rgbCertificateHash;
    UINT32 ulEntityDigestLength;



    BYTE* rgbentityDigest;
    TSS_BOOL fDigestChecked;
    TSS_BOOL fDigestVerified;
    UINT32 ulIssuerLength;



    BYTE* rgbIssuer;
} TSS_EVENT_CERT;

typedef struct tdTSS_UUID
{
    UINT32 ulTimeLow;
    UINT16 usTimeMid;
    UINT16 usTimeHigh;
    BYTE bClockSeqHigh;
    BYTE bClockSeqLow;
    BYTE rgbNode[6];
} TSS_UUID;

typedef struct tdTSS_KM_KEYINFO
{
    TSS_VERSION versionInfo;
    TSS_UUID keyUUID;
    TSS_UUID parentKeyUUID;
    BYTE bAuthDataUsage;
    TSS_BOOL fIsLoaded;
    UINT32 ulVendorDataLength;



    BYTE *rgbVendorData;
} TSS_KM_KEYINFO;


typedef struct tdTSS_KM_KEYINFO2
{
    TSS_VERSION versionInfo;
    TSS_UUID keyUUID;
    TSS_UUID parentKeyUUID;
    BYTE bAuthDataUsage;
    TSS_FLAG persistentStorageType;
    TSS_FLAG persistentStorageTypeParent;
    TSS_BOOL fIsLoaded;
    UINT32 ulVendorDataLength;



    BYTE *rgbVendorData;
} TSS_KM_KEYINFO2;


typedef struct tdTSS_NONCE
{
    BYTE nonce[0x14];
} TSS_NONCE;


typedef struct tdTSS_VALIDATION
{
    TSS_VERSION versionInfo;
    UINT32 ulExternalDataLength;



    BYTE* rgbExternalData;
    UINT32 ulDataLength;



    BYTE* rgbData;
    UINT32 ulValidationDataLength;



    BYTE* rgbValidationData;
} TSS_VALIDATION;


typedef struct tdTSS_CALLBACK
{
    PVOID callback;
    PVOID appData;
    TSS_ALGORITHM_ID alg;
} TSS_CALLBACK;


typedef struct tdTSS_DAA_PK
{
    TSS_VERSION versionInfo;
    UINT32 modulusLength;



    BYTE* modulus;
    UINT32 capitalSLength;



    BYTE* capitalS;
    UINT32 capitalZLength;



    BYTE* capitalZ;
    UINT32 capitalR0Length;



    BYTE* capitalR0;
    UINT32 capitalR1Length;



    BYTE* capitalR1;
    UINT32 gammaLength;



    BYTE* gamma;
    UINT32 capitalGammaLength;



    BYTE* capitalGamma;
    UINT32 rhoLength;



    BYTE* rho;
    UINT32 capitalYLength;
    UINT32 capitalYLength2;



    BYTE** capitalY;
    UINT32 capitalYPlatformLength;
    UINT32 issuerBaseNameLength;



    BYTE* issuerBaseName;
    UINT32 numPlatformAttributes;
    UINT32 numIssuerAttributes;
} TSS_DAA_PK;

typedef struct tdTSS_DAA_PK_PROOF
{
    TSS_VERSION versionInfo;
    UINT32 challengeLength;



    BYTE* challenge;
    UINT32 responseLength;
    UINT32 responseLength2;



    BYTE** response;
} TSS_DAA_PK_PROOF;

typedef struct tdTSS_DAA_SK
{
    TSS_VERSION versionInfo;
    UINT32 productPQprimeLength;



    BYTE* productPQprime;
} TSS_DAA_SK;


typedef struct tdTSS_DAA_KEY_PAIR
{
    TSS_VERSION versionInfo;
    TSS_DAA_SK secretKey;
    TSS_DAA_PK publicKey;
} TSS_DAA_KEY_PAIR;

typedef struct tdTSS_DAA_AR_PK
{
    TSS_VERSION versionInfo;
    UINT32 etaLength;



    BYTE* eta;
    UINT32 lambda1Length;



    BYTE* lambda1;
    UINT32 lambda2Length;



    BYTE* lambda2;
    UINT32 lambda3Length;



    BYTE* lambda3;
} TSS_DAA_AR_PK;

typedef struct tdTSS_DAA_AR_SK
{
    TSS_VERSION versionInfo;
    UINT32 x0Length;



    BYTE* x0;
    UINT32 x1Length;



    BYTE* x1;
    UINT32 x2Length;



    BYTE* x2;
    UINT32 x3Length;



    BYTE* x3;
    UINT32 x4Length;



    BYTE* x4;
    UINT32 x5Length;



    BYTE* x5;
} TSS_DAA_AR_SK;

typedef struct tdTSS_DAA_AR_KEY_PAIR
{
    TSS_VERSION versionInfo;
    TSS_DAA_AR_SK secretKey;
    TSS_DAA_AR_PK publicKey;
} TSS_DAA_AR_KEY_PAIR;

typedef struct tdTSS_DAA_CRED_ISSUER
{
    TSS_VERSION versionInfo;
    UINT32 capitalALength;



    BYTE* capitalA;
    UINT32 eLength;



    BYTE* e;
    UINT32 vPrimePrimeLength;



    BYTE* vPrimePrime;
    UINT32 attributesIssuerLength;
    UINT32 attributesIssuerLength2;



    BYTE** attributesIssuer;
    UINT32 cPrimeLength;



    BYTE* cPrime;
    UINT32 sELength;



    BYTE* sE;
} TSS_DAA_CRED_ISSUER;

typedef struct tdTSS_DAA_CREDENTIAL
{
    TSS_VERSION versionInfo;
    UINT32 capitalALength;



    BYTE* capitalA;
    UINT32 exponentLength;



    BYTE* exponent;
    UINT32 vBar0Length;



    BYTE* vBar0;
    UINT32 vBar1Length;



    BYTE* vBar1;
    UINT32 attributesLength;
    UINT32 attributesLength2;



    BYTE** attributes;
    TSS_DAA_PK issuerPK;
    UINT32 tpmSpecificEncLength;



    BYTE* tpmSpecificEnc;
    UINT32 daaCounter;
} TSS_DAA_CREDENTIAL;

typedef struct tdTSS_DAA_ATTRIB_COMMIT
{
    TSS_VERSION versionInfo;
    UINT32 betaLength;



    BYTE* beta;
    UINT32 sMuLength;



    BYTE* sMu;
} TSS_DAA_ATTRIB_COMMIT;

typedef struct tdTSS_DAA_CREDENTIAL_REQUEST
{
    TSS_VERSION versionInfo;
    UINT32 capitalULength;



    BYTE* capitalU;
    UINT32 capitalNiLength;



    BYTE* capitalNi;
    UINT32 authenticationProofLength;



    BYTE* authenticationProof;
    UINT32 challengeLength;



    BYTE* challenge;
    UINT32 nonceTpmLength;



    BYTE* nonceTpm;
    UINT32 noncePlatformLength;



    BYTE* noncePlatform;
    UINT32 sF0Length;



    BYTE* sF0;
    UINT32 sF1Length;



    BYTE* sF1;
    UINT32 sVprimeLength;



    BYTE* sVprime;
    UINT32 sVtildePrimeLength;



    BYTE* sVtildePrime;
    UINT32 sALength;
    UINT32 sALength2;



    BYTE** sA;
    UINT32 attributeCommitmentsLength;
    TSS_DAA_ATTRIB_COMMIT* attributeCommitments;
} TSS_DAA_CREDENTIAL_REQUEST;

typedef struct tdTSS_DAA_SELECTED_ATTRIB
{
    TSS_VERSION versionInfo;
    UINT32 indicesListLength;



    TSS_BOOL* indicesList;
} TSS_DAA_SELECTED_ATTRIB;

typedef struct tdTSS_DAA_PSEUDONYM
{
    TSS_VERSION versionInfo;
    TSS_FLAG payloadFlag;
    UINT32 payloadLength;



    BYTE* payload;
} TSS_DAA_PSEUDONYM;

typedef struct tdTSS_DAA_PSEUDONYM_PLAIN
{
    TSS_VERSION versionInfo;
    UINT32 capitalNvLength;



    BYTE* capitalNv;
} TSS_DAA_PSEUDONYM_PLAIN;

typedef struct tdTSS_DAA_PSEUDONYM_ENCRYPTED
{
    TSS_VERSION versionInfo;
    UINT32 delta1Length;



    BYTE* delta1;
    UINT32 delta2Length;



    BYTE* delta2;
    UINT32 delta3Length;



    BYTE* delta3;
    UINT32 delta4Length;



    BYTE* delta4;
    UINT32 sTauLength;



    BYTE* sTau;
} TSS_DAA_PSEUDONYM_ENCRYPTED;

typedef struct tdTSS_DAA_SIGN_CALLBACK
{
    TSS_VERSION versionInfo;
    TSS_HHASH challenge;
    TSS_FLAG payloadFlag;
    UINT32 payloadLength;



    BYTE* payload;
} TSS_DAA_SIGN_CALLBACK;

typedef struct tdTSS_DAA_SIGNATURE
{
    TSS_VERSION versionInfo;
    UINT32 zetaLength;



    BYTE* zeta;
    UINT32 capitalTLength;



    BYTE* capitalT;
    UINT32 challengeLength;



    BYTE* challenge;
    UINT32 nonceTpmLength;



    BYTE* nonceTpm;
    UINT32 sVLength;



    BYTE* sV;
    UINT32 sF0Length;



    BYTE* sF0;
    UINT32 sF1Length;



    BYTE* sF1;
    UINT32 sELength;



    BYTE* sE;
    UINT32 sALength;
    UINT32 sALength2;



    BYTE** sA;
    UINT32 attributeCommitmentsLength;



    TSS_DAA_ATTRIB_COMMIT* attributeCommitments;
    TSS_DAA_PSEUDONYM signedPseudonym;
    TSS_DAA_SIGN_CALLBACK callbackResult;
} TSS_DAA_SIGNATURE;

typedef struct tdTSS_DAA_IDENTITY_PROOF
{
    TSS_VERSION versionInfo;
    UINT32 endorsementLength;



    BYTE* endorsementCredential;
    UINT32 platformLength;



    BYTE* platform;
    UINT32 conformanceLength;



    BYTE* conformance;
} TSS_DAA_IDENTITY_PROOF;




typedef UINT32 TSS_FAMILY_ID;
typedef BYTE TSS_DELEGATION_LABEL;

typedef UINT32 TSS_DELEGATION_TYPE;

typedef struct tdTSS_PCR_INFO_SHORT
{
    UINT32 sizeOfSelect;



    BYTE *selection;
    BYTE localityAtRelease;
    UINT32 sizeOfDigestAtRelease;



    BYTE *digestAtRelease;
} TSS_PCR_INFO_SHORT;

typedef struct tdTSS_FAMILY_TABLE_ENTRY
{
    TSS_FAMILY_ID familyID;
    TSS_DELEGATION_LABEL label;
    UINT32 verificationCount;
    TSS_BOOL enabled;
    TSS_BOOL locked;
} TSS_FAMILY_TABLE_ENTRY;

typedef struct tdTSS_DELEGATION_TABLE_ENTRY
{
    UINT32 tableIndex;
    TSS_DELEGATION_LABEL label;
    TSS_PCR_INFO_SHORT pcrInfo;
    UINT32 per1;
    UINT32 per2;
    TSS_FAMILY_ID familyID;
    UINT32 verificationCount;
} TSS_DELEGATION_TABLE_ENTRY;

typedef struct tdTSS_PLATFORM_CLASS
{
    UINT32 platformClassSimpleIdentifier;
    UINT32 platformClassURISize;
    BYTE* pPlatformClassURI;
} TSS_PLATFORM_CLASS;


typedef UINT32 TCS_AUTHHANDLE;
typedef UINT32 TCS_CONTEXT_HANDLE;
typedef UINT32 TCS_KEY_HANDLE;
typedef UINT32 TCS_HANDLE;



typedef TPM_ENCAUTH TCG_ENCAUTH;
typedef TPM_NONCE TCG_NONCE;
typedef TPM_ENTITY_TYPE TCG_ENTITY_TYPE;
typedef TPM_PCRINDEX TCG_PCRINDEX;
typedef TPM_DIGEST TCG_DIGEST;
typedef TPM_PCRVALUE TCG_PCRVALUE;
typedef TPM_DIRVALUE TCG_DIRVALUE;
typedef TPM_DIRINDEX TCG_DIRINDEX;


typedef struct tdTCS_AUTH
{
    TCS_AUTHHANDLE AuthHandle;
    TPM_NONCE NonceOdd;
    TPM_NONCE NonceEven;
    TSS_BOOL fContinueAuthSession;
    TPM_AUTHDATA HMAC;
} TCS_AUTH;


typedef TCS_AUTH TPM_AUTH;


typedef struct tdTCS_LOADKEY_INFO
{
    TSS_UUID keyUUID;
    TSS_UUID parentKeyUUID;
    TPM_DIGEST paramDigest;


    TPM_AUTH authData;


} TCS_LOADKEY_INFO;

extern TSS_RESULT Tspi_EncodeDER_TssBlob
(
    UINT32 rawBlobSize,
    BYTE* rawBlob,
    UINT32 blobType,
    UINT32* derBlobSize,
    BYTE* derBlob
);

extern TSS_RESULT Tspi_DecodeBER_TssBlob
(
    UINT32 berBlobSize,
    BYTE* berBlob,
    UINT32* blobType,
    UINT32* rawBlobSize,
    BYTE* rawBlob
);




extern TSS_RESULT Tspi_SetAttribUint32
(
    TSS_HOBJECT hObject,
    TSS_FLAG attribFlag,
    TSS_FLAG subFlag,
    UINT32 ulAttrib
);

extern TSS_RESULT Tspi_GetAttribUint32
(
    TSS_HOBJECT hObject,
    TSS_FLAG attribFlag,
    TSS_FLAG subFlag,
    UINT32* pulAttrib
);

extern TSS_RESULT Tspi_SetAttribData
(
    TSS_HOBJECT hObject,
    TSS_FLAG attribFlag,
    TSS_FLAG subFlag,
    UINT32 ulAttribDataSize,
    BYTE* rgbAttribData
);

extern TSS_RESULT Tspi_GetAttribData
(
    TSS_HOBJECT hObject,
    TSS_FLAG attribFlag,
    TSS_FLAG subFlag,
    UINT32* pulAttribDataSize,
    BYTE** prgbAttribData
);

extern TSS_RESULT Tspi_ChangeAuth
(
    TSS_HOBJECT hObjectToChange,
    TSS_HOBJECT hParentObject,
    TSS_HPOLICY hNewPolicy
);

extern TSS_RESULT Tspi_ChangeAuthAsym
(
    TSS_HOBJECT hObjectToChange,
    TSS_HOBJECT hParentObject,
    TSS_HKEY hIdentKey,
    TSS_HPOLICY hNewPolicy
);

extern TSS_RESULT Tspi_GetPolicyObject
(
    TSS_HOBJECT hObject,
    TSS_FLAG policyType,
    TSS_HPOLICY* phPolicy
);




extern TSS_RESULT Tspi_Context_Create
(
    TSS_HCONTEXT* phContext
);

extern TSS_RESULT Tspi_Context_Close
(
    TSS_HCONTEXT hContext
);

extern TSS_RESULT Tspi_Context_Connect
(
    TSS_HCONTEXT hContext,
    TSS_UNICODE* wszDestination
);

extern TSS_RESULT Tspi_Context_FreeMemory
(
    TSS_HCONTEXT hContext,
    BYTE* rgbMemory
);

extern TSS_RESULT Tspi_Context_GetDefaultPolicy
(
    TSS_HCONTEXT hContext,
    TSS_HPOLICY* phPolicy
);

extern TSS_RESULT Tspi_Context_CreateObject
(
    TSS_HCONTEXT hContext,
    TSS_FLAG objectType,
    TSS_FLAG initFlags,
    TSS_HOBJECT* phObject
);

extern TSS_RESULT Tspi_Context_CloseObject
(
    TSS_HCONTEXT hContext,
    TSS_HOBJECT hObject
);

extern TSS_RESULT Tspi_Context_GetCapability
(
    TSS_HCONTEXT hContext,
    TSS_FLAG capArea,
    UINT32 ulSubCapLength,
    BYTE* rgbSubCap,
    UINT32* pulRespDataLength,
    BYTE** prgbRespData
);

extern TSS_RESULT Tspi_Context_GetTpmObject
(
    TSS_HCONTEXT hContext,
    TSS_HTPM* phTPM
);

extern TSS_RESULT Tspi_Context_SetTransEncryptionKey
(
    TSS_HCONTEXT hContext,
    TSS_HKEY hKey
);

extern TSS_RESULT Tspi_Context_CloseSignTransport
(
    TSS_HCONTEXT hContext,
    TSS_HKEY hSigningKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_Context_LoadKeyByBlob
(
    TSS_HCONTEXT hContext,
    TSS_HKEY hUnwrappingKey,
    UINT32 ulBlobLength,
    BYTE* rgbBlobData,
    TSS_HKEY* phKey
);

extern TSS_RESULT Tspi_Context_LoadKeyByUUID
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_UUID uuidData,
    TSS_HKEY* phKey
);

extern TSS_RESULT Tspi_Context_RegisterKey
(
    TSS_HCONTEXT hContext,
    TSS_HKEY hKey,
    TSS_FLAG persistentStorageType,
    TSS_UUID uuidKey,
    TSS_FLAG persistentStorageTypeParent,
    TSS_UUID uuidParentKey
);

extern TSS_RESULT Tspi_Context_UnregisterKey
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_UUID uuidKey,
    TSS_HKEY* phkey
);

extern TSS_RESULT Tspi_Context_GetKeyByUUID
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_UUID uuidData,
    TSS_HKEY* phKey
);

extern TSS_RESULT Tspi_Context_GetKeyByPublicInfo
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_ALGORITHM_ID algID,
    UINT32 ulPublicInfoLength,
    BYTE* rgbPublicInfo,
    TSS_HKEY* phKey
);

extern TSS_RESULT Tspi_Context_GetRegisteredKeysByUUID
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_UUID* pUuidData,
    UINT32* pulKeyHierarchySize,
    TSS_KM_KEYINFO** ppKeyHierarchy
);

extern TSS_RESULT Tspi_Context_GetRegisteredKeysByUUID2
(
    TSS_HCONTEXT hContext,
    TSS_FLAG persistentStorageType,
    TSS_UUID* pUuidData,
    UINT32* pulKeyHierarchySize,
    TSS_KM_KEYINFO2** ppKeyHierarchy
);



extern TSS_RESULT Tspi_Policy_SetSecret
(
    TSS_HPOLICY hPolicy,
    TSS_FLAG secretMode,
    UINT32 ulSecretLength,
    BYTE* rgbSecret
);

extern TSS_RESULT Tspi_Policy_FlushSecret
(
    TSS_HPOLICY hPolicy
);

extern TSS_RESULT Tspi_Policy_AssignToObject
(
    TSS_HPOLICY hPolicy,
    TSS_HOBJECT hObject
);




extern TSS_RESULT Tspi_TPM_KeyControlOwner
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    UINT32 attribName,
    TSS_BOOL attribValue,
    TSS_UUID* pUuidData
);

extern TSS_RESULT Tspi_TPM_CreateEndorsementKey
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_TPM_CreateRevocableEndorsementKey
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    TSS_VALIDATION* pValidationData,
    UINT32* pulEkResetDataLength,
    BYTE** rgbEkResetData
);

extern TSS_RESULT Tspi_TPM_RevokeEndorsementKey
(
    TSS_HTPM hTPM,
    UINT32 ulEkResetDataLength,
    BYTE* rgbEkResetData
);

extern TSS_RESULT Tspi_TPM_GetPubEndorsementKey
(
    TSS_HTPM hTPM,
    TSS_BOOL fOwnerAuthorized,
    TSS_VALIDATION* pValidationData,
    TSS_HKEY* phEndorsementPubKey
);

extern TSS_RESULT Tspi_TPM_OwnerGetSRKPubKey
(
    TSS_HTPM hTPM,
    UINT32* pulPubKeyLength,
    BYTE** prgbPubKey
);

extern TSS_RESULT Tspi_TPM_TakeOwnership
(
    TSS_HTPM hTPM,
    TSS_HKEY hKeySRK,
    TSS_HKEY hEndorsementPubKey
);

extern TSS_RESULT Tspi_TPM_ClearOwner
(
    TSS_HTPM hTPM,
    TSS_BOOL fForcedClear
);

extern TSS_RESULT Tspi_TPM_CollateIdentityRequest
(
    TSS_HTPM hTPM,
    TSS_HKEY hKeySRK,
    TSS_HKEY hCAPubKey,
    UINT32 ulIdentityLabelLength,
    BYTE* rgbIdentityLabelData,
    TSS_HKEY hIdentityKey,
    TSS_ALGORITHM_ID algID,
    UINT32* pulTCPAIdentityReqLength,
    BYTE** prgbTCPAIdentityReq
);

extern TSS_RESULT Tspi_TPM_ActivateIdentity
(
    TSS_HTPM hTPM,
    TSS_HKEY hIdentKey,
    UINT32 ulAsymCAContentsBlobLength,
    BYTE* rgbAsymCAContentsBlob,
    UINT32 ulSymCAAttestationBlobLength,
    BYTE* rgbSymCAAttestationBlob,
    UINT32* pulCredentialLength,
    BYTE** prgbCredential
);

extern TSS_RESULT Tspi_TPM_CreateMaintenanceArchive
(
    TSS_HTPM hTPM,
    TSS_BOOL fGenerateRndNumber,
    UINT32* pulRndNumberLength,
    BYTE** prgbRndNumber,
    UINT32* pulArchiveDataLength,
    BYTE** prgbArchiveData
);

extern TSS_RESULT Tspi_TPM_KillMaintenanceFeature
(
    TSS_HTPM hTPM
);

extern TSS_RESULT Tspi_TPM_LoadMaintenancePubKey
(
    TSS_HTPM hTPM,
    TSS_HKEY hMaintenanceKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_TPM_CheckMaintenancePubKey
(
    TSS_HTPM hTPM,
    TSS_HKEY hMaintenanceKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_TPM_SetOperatorAuth
(
    TSS_HTPM hTPM,
    TSS_HPOLICY hOperatorPolicy
);

extern TSS_RESULT Tspi_TPM_SetStatus
(
    TSS_HTPM hTPM,
    TSS_FLAG statusFlag,
    TSS_BOOL fTpmState
);

extern TSS_RESULT Tspi_TPM_GetStatus
(
    TSS_HTPM hTPM,
    TSS_FLAG statusFlag,
    TSS_BOOL* pfTpmState
);

extern TSS_RESULT Tspi_TPM_GetCapability
(
    TSS_HTPM hTPM,
    TSS_FLAG capArea,
    UINT32 ulSubCapLength,
    BYTE* rgbSubCap,
    UINT32* pulRespDataLength,
    BYTE** prgbRespData
);

extern TSS_RESULT Tspi_TPM_GetCapabilitySigned
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    TSS_FLAG capArea,
    UINT32 ulSubCapLength,
    BYTE* rgbSubCap,
    TSS_VALIDATION* pValidationData,
    UINT32* pulRespDataLength,
    BYTE** prgbRespData
);

extern TSS_RESULT Tspi_TPM_SelfTestFull
(
    TSS_HTPM hTPM
);

extern TSS_RESULT Tspi_TPM_CertifySelfTest
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_TPM_GetTestResult
(
    TSS_HTPM hTPM,
    UINT32* pulTestResultLength,
    BYTE** prgbTestResult
);

extern TSS_RESULT Tspi_TPM_GetRandom
(
    TSS_HTPM hTPM,
    UINT32 ulRandomDataLength,
    BYTE** prgbRandomData
);

extern TSS_RESULT Tspi_TPM_StirRandom
(
    TSS_HTPM hTPM,
    UINT32 ulEntropyDataLength,
    BYTE* rgbEntropyData
);

extern TSS_RESULT Tspi_TPM_GetEvent
(
    TSS_HTPM hTPM,
    UINT32 ulPcrIndex,
    UINT32 ulEventNumber,
    TSS_PCR_EVENT* pPcrEvent
);

extern TSS_RESULT Tspi_TPM_GetEvents
(
    TSS_HTPM hTPM,
    UINT32 ulPcrIndex,
    UINT32 ulStartNumber,
    UINT32* pulEventNumber,
    TSS_PCR_EVENT** prgPcrEvents
);

extern TSS_RESULT Tspi_TPM_GetEventLog
(
    TSS_HTPM hTPM,
    UINT32* pulEventNumber,
    TSS_PCR_EVENT** prgPcrEvents
);

extern TSS_RESULT Tspi_TPM_Quote
(
    TSS_HTPM hTPM,
    TSS_HKEY hIdentKey,
    TSS_HPCRS hPcrComposite,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_TPM_Quote2
(
    TSS_HTPM hTPM,
    TSS_HKEY hIdentKey,
    TSS_BOOL fAddVersion,
    TSS_HPCRS hPcrComposite,
    TSS_VALIDATION* pValidationData,
    UINT32* versionInfoSize,
    BYTE** versionInfo
);

extern TSS_RESULT Tspi_TPM_PcrExtend
(
    TSS_HTPM hTPM,
    UINT32 ulPcrIndex,
    UINT32 ulPcrDataLength,
    BYTE* pbPcrData,
    TSS_PCR_EVENT* pPcrEvent,
    UINT32* pulPcrValueLength,
    BYTE** prgbPcrValue
);

extern TSS_RESULT Tspi_TPM_PcrRead
(
    TSS_HTPM hTPM,
    UINT32 ulPcrIndex,
    UINT32* pulPcrValueLength,
    BYTE** prgbPcrValue
);

extern TSS_RESULT Tspi_TPM_PcrReset
(
    TSS_HTPM hTPM,
    TSS_HPCRS hPcrComposite
);

extern TSS_RESULT Tspi_TPM_AuthorizeMigrationTicket
(
    TSS_HTPM hTPM,
    TSS_HKEY hMigrationKey,
    TSS_MIGRATE_SCHEME migrationScheme,
    UINT32* pulMigTicketLength,
    BYTE** prgbMigTicket
);

extern TSS_RESULT Tspi_TPM_CMKSetRestrictions
(
    TSS_HTPM hTPM,
    TSS_CMK_DELEGATE CmkDelegate
);

extern TSS_RESULT Tspi_TPM_CMKApproveMA
(
    TSS_HTPM hTPM,
    TSS_HMIGDATA hMaAuthData
);

extern TSS_RESULT Tspi_TPM_CMKCreateTicket
(
    TSS_HTPM hTPM,
    TSS_HKEY hVerifyKey,
    TSS_HMIGDATA hSigData
);

extern TSS_RESULT Tspi_TPM_ReadCounter
(
    TSS_HTPM hTPM,
    UINT32* counterValue
);

extern TSS_RESULT Tspi_TPM_ReadCurrentTicks
(
    TSS_HTPM hTPM,
    TPM_CURRENT_TICKS* tickCount
);

extern TSS_RESULT Tspi_TPM_DirWrite
(
    TSS_HTPM hTPM,
    UINT32 ulDirIndex,
    UINT32 ulDirDataLength,
    BYTE* rgbDirData
);

extern TSS_RESULT Tspi_TPM_DirRead
(
    TSS_HTPM hTPM,
    UINT32 ulDirIndex,
    UINT32* pulDirDataLength,
    BYTE** prgbDirData
);

extern TSS_RESULT Tspi_TPM_Delegate_AddFamily
(
    TSS_HTPM hTPM,
    BYTE bLabel,
    TSS_HDELFAMILY* phFamily
);

extern TSS_RESULT Tspi_TPM_Delegate_GetFamily
(
    TSS_HTPM hTPM,
    UINT32 ulFamilyID,
    TSS_HDELFAMILY* phFamily
);

extern TSS_RESULT Tspi_TPM_Delegate_InvalidateFamily
(
    TSS_HTPM hTPM,
    TSS_HDELFAMILY hFamily
);

extern TSS_RESULT Tspi_TPM_Delegate_CreateDelegation
(
    TSS_HOBJECT hObject,
    BYTE bLabel,
    UINT32 ulFlags,
    TSS_HPCRS hPcr,
    TSS_HDELFAMILY hFamily,
    TSS_HPOLICY hDelegation
);

extern TSS_RESULT Tspi_TPM_Delegate_CacheOwnerDelegation
(
    TSS_HTPM hTPM,
    TSS_HPOLICY hDelegation,
    UINT32 ulIndex,
    UINT32 ulFlags
);

extern TSS_RESULT Tspi_TPM_Delegate_UpdateVerificationCount
(
    TSS_HTPM hTPM,
    TSS_HPOLICY hDelegation
);

extern TSS_RESULT Tspi_TPM_Delegate_VerifyDelegation
(
    TSS_HPOLICY hDelegation
);

extern TSS_RESULT Tspi_TPM_Delegate_ReadTables
(
    TSS_HCONTEXT hContext,
    UINT32* pulFamilyTableSize,
    TSS_FAMILY_TABLE_ENTRY** ppFamilyTable,
    UINT32* pulDelegateTableSize,
    TSS_DELEGATION_TABLE_ENTRY** ppDelegateTable
);

extern TSS_RESULT Tspi_TPM_GetAuditDigest
(
    TSS_HTPM hTPM,
    TSS_HKEY hKey,
    TSS_BOOL closeAudit,
    UINT32* pulAuditDigestSize,
    BYTE** prgbAuditDigest,
    TPM_COUNTER_VALUE* pCounterValue,
    TSS_VALIDATION* pValidationData,
    UINT32* ordSize,
    UINT32** ordList
);




extern TSS_RESULT Tspi_PcrComposite_SelectPcrIndex
(
    TSS_HPCRS hPcrComposite,
    UINT32 ulPcrIndex
);

extern TSS_RESULT Tspi_PcrComposite_SelectPcrIndexEx
(
    TSS_HPCRS hPcrComposite,
    UINT32 ulPcrIndex,
    UINT32 direction
);

extern TSS_RESULT Tspi_PcrComposite_SetPcrValue
(
    TSS_HPCRS hPcrComposite,
    UINT32 ulPcrIndex,
    UINT32 ulPcrValueLength,
    BYTE* rgbPcrValue
);

extern TSS_RESULT Tspi_PcrComposite_GetPcrValue
(
    TSS_HPCRS hPcrComposite,
    UINT32 ulPcrIndex,
    UINT32* pulPcrValueLength,
    BYTE** prgbPcrValue
);

extern TSS_RESULT Tspi_PcrComposite_SetPcrLocality
(
    TSS_HPCRS hPcrComposite,
    UINT32 LocalityValue
);

extern TSS_RESULT Tspi_PcrComposite_GetPcrLocality
(
    TSS_HPCRS hPcrComposite,
    UINT32* pLocalityValue
);

extern TSS_RESULT Tspi_PcrComposite_GetCompositeHash
(
    TSS_HPCRS hPcrComposite,
    UINT32* pLen,
    BYTE** ppbHashData
);




extern TSS_RESULT Tspi_Key_LoadKey
(
    TSS_HKEY hKey,
    TSS_HKEY hUnwrappingKey
);

extern TSS_RESULT Tspi_Key_UnloadKey
(
    TSS_HKEY hKey
);

extern TSS_RESULT Tspi_Key_GetPubKey
(
    TSS_HKEY hKey,
    UINT32* pulPubKeyLength,
    BYTE** prgbPubKey
);

extern TSS_RESULT Tspi_Key_CertifyKey
(
    TSS_HKEY hKey,
    TSS_HKEY hCertifyingKey,
    TSS_VALIDATION* pValidationData
);

extern TSS_RESULT Tspi_Key_CreateKey
(
    TSS_HKEY hKey,
    TSS_HKEY hWrappingKey,
    TSS_HPCRS hPcrComposite
);

extern TSS_RESULT Tspi_Key_WrapKey
(
    TSS_HKEY hKey,
    TSS_HKEY hWrappingKey,
    TSS_HPCRS hPcrComposite
);

extern TSS_RESULT Tspi_Key_CreateMigrationBlob
(
    TSS_HKEY hKeyToMigrate,
    TSS_HKEY hParentKey,
    UINT32 ulMigTicketLength,
    BYTE* rgbMigTicket,
    UINT32* pulRandomLength,
    BYTE** prgbRandom,
    UINT32* pulMigrationBlobLength,
    BYTE** prgbMigrationBlob
);

extern TSS_RESULT Tspi_Key_ConvertMigrationBlob
(
    TSS_HKEY hKeyToMigrate,
    TSS_HKEY hParentKey,
    UINT32 ulRandomLength,
    BYTE* rgbRandom,
    UINT32 ulMigrationBlobLength,
    BYTE* rgbMigrationBlob
);

extern TSS_RESULT Tspi_Key_CMKCreateBlob
(
    TSS_HKEY hKeyToMigrate,
    TSS_HKEY hParentKey,
    TSS_HMIGDATA hMigrationData,
    UINT32* pulRandomLength,
    BYTE** prgbRandom
);

extern TSS_RESULT Tspi_Key_CMKConvertMigration
(
    TSS_HKEY hKeyToMigrate,
    TSS_HKEY hParentKey,
    TSS_HMIGDATA hMigrationData,
    UINT32 ulRandomLength,
    BYTE* rgbRandom
);




extern TSS_RESULT Tspi_Hash_Sign
(
    TSS_HHASH hHash,
    TSS_HKEY hKey,
    UINT32* pulSignatureLength,
    BYTE** prgbSignature
);

extern TSS_RESULT Tspi_Hash_VerifySignature
(
    TSS_HHASH hHash,
    TSS_HKEY hKey,
    UINT32 ulSignatureLength,
    BYTE* rgbSignature
);

extern TSS_RESULT Tspi_Hash_SetHashValue
(
    TSS_HHASH hHash,
    UINT32 ulHashValueLength,
    BYTE* rgbHashValue
);

extern TSS_RESULT Tspi_Hash_GetHashValue
(
    TSS_HHASH hHash,
    UINT32* pulHashValueLength,
    BYTE** prgbHashValue
);

extern TSS_RESULT Tspi_Hash_UpdateHashValue
(
    TSS_HHASH hHash,
    UINT32 ulDataLength,
    BYTE* rgbData
);

extern TSS_RESULT Tspi_Hash_TickStampBlob
(
    TSS_HHASH hHash,
    TSS_HKEY hIdentKey,
    TSS_VALIDATION* pValidationData
);




extern TSS_RESULT Tspi_Data_Bind
(
    TSS_HENCDATA hEncData,
    TSS_HKEY hEncKey,
    UINT32 ulDataLength,
    BYTE* rgbDataToBind
);

extern TSS_RESULT Tspi_Data_Unbind
(
    TSS_HENCDATA hEncData,
    TSS_HKEY hKey,
    UINT32* pulUnboundDataLength,
    BYTE** prgbUnboundData
);

extern TSS_RESULT Tspi_Data_Seal
(
    TSS_HENCDATA hEncData,
    TSS_HKEY hEncKey,
    UINT32 ulDataLength,
    BYTE* rgbDataToSeal,
    TSS_HPCRS hPcrComposite
);

extern TSS_RESULT Tspi_Data_Unseal
(
    TSS_HENCDATA hEncData,
    TSS_HKEY hKey,
    UINT32* pulUnsealedDataLength,
    BYTE** prgbUnsealedData
);




extern TSS_RESULT Tspi_NV_DefineSpace
(
    TSS_HNVSTORE hNVStore,
    TSS_HPCRS hReadPcrComposite,
    TSS_HPCRS hWritePcrComposite
);

extern TSS_RESULT Tspi_NV_ReleaseSpace
(
    TSS_HNVSTORE hNVStore
);

extern TSS_RESULT Tspi_NV_WriteValue
(
    TSS_HNVSTORE hNVStore,
    UINT32 offset,
    UINT32 ulDataLength,
    BYTE* rgbDataToWrite
);

extern TSS_RESULT Tspi_NV_ReadValue
(
    TSS_HNVSTORE hNVStore,
    UINT32 offset,
    UINT32* ulDataLength,
    BYTE** rgbDataRead
);


typedef TSS_RESULT (*Tspicb_CallbackHMACAuth)
(
    PVOID lpAppData,
    TSS_HOBJECT hAuthorizedObject,
    TSS_BOOL ReturnOrVerify,
    UINT32 ulPendingFunction,
    TSS_BOOL ContinueUse,
    UINT32 ulSizeNonces,
    BYTE* rgbNonceEven,
    BYTE* rgbNonceOdd,
    BYTE* rgbNonceEvenOSAP,
    BYTE* rgbNonceOddOSAP,
    UINT32 ulSizeDigestHmac,
    BYTE* rgbParamDigest,
    BYTE* rgbHmacData
);

typedef TSS_RESULT (*Tspicb_CallbackXorEnc)
(
   PVOID lpAppData,
   TSS_HOBJECT hOSAPObject,
   TSS_HOBJECT hObject,
   TSS_FLAG PurposeSecret,
   UINT32 ulSizeNonces,
   BYTE* rgbNonceEven,
   BYTE* rgbNonceOdd,
   BYTE* rgbNonceEvenOSAP,
   BYTE* rgbNonceOddOSAP,
   UINT32 ulSizeEncAuth,
   BYTE* rgbEncAuthUsage,
   BYTE* rgbEncAuthMigration
);

typedef TSS_RESULT (*Tspicb_CallbackTakeOwnership)
(
   PVOID lpAppData,
   TSS_HOBJECT hObject,
   TSS_HKEY hObjectPubKey,
   UINT32 ulSizeEncAuth,
   BYTE* rgbEncAuth
);

typedef TSS_RESULT (*Tspicb_CallbackSealxMask)
(
    PVOID lpAppData,
    TSS_HKEY hKey,
    TSS_HENCDATA hEncData,
    TSS_ALGORITHM_ID algID,
    UINT32 ulSizeNonces,
    BYTE* rgbNonceEven,
    BYTE* rgbNonceOdd,
    BYTE* rgbNonceEvenOSAP,
    BYTE* rgbNonceOddOSAP,
    UINT32 ulDataLength,
    BYTE* rgbDataToMask,
    BYTE* rgbMaskedData
);

typedef TSS_RESULT (*Tspicb_CallbackChangeAuthAsym)
(
   PVOID lpAppData,
   TSS_HOBJECT hObject,
   TSS_HKEY hObjectPubKey,
   UINT32 ulSizeEncAuth,
   UINT32 ulSizeAuthLink,
   BYTE* rgbEncAuth,
   BYTE* rgbAuthLink
);

typedef TSS_RESULT (*Tspicb_CollateIdentity)
(
   PVOID lpAppData,
   UINT32 ulTCPAPlainIdentityProofLength,
   BYTE* rgbTCPAPlainIdentityProof,
   TSS_ALGORITHM_ID algID,
   UINT32 ulSessionKeyLength,
   BYTE* rgbSessionKey,
   UINT32* pulTCPAIdentityProofLength,
   BYTE* rgbTCPAIdentityProof
);


typedef TSS_RESULT (*Tspicb_ActivateIdentity)
(
   PVOID lpAppData,
   UINT32 ulSessionKeyLength,
   BYTE* rgbSessionKey,
   UINT32 ulSymCAAttestationBlobLength,
   BYTE* rgbSymCAAttestationBlob,
   UINT32* pulCredentialLength,
   BYTE* rgbCredential
);


typedef TSS_RESULT (*Tspicb_DAA_Sign)
(
    PVOID lpAppData,
    TSS_HDAA_ISSUER_KEY daaPublicKey,
    UINT32 gammasLength,
    BYTE** gammas,
    UINT32 attributesLength,
    BYTE** attributes,
    UINT32 randomAttributesLength,
    BYTE** randomAttributes,
    UINT32 attributeCommitmentsLength,
    TSS_DAA_ATTRIB_COMMIT* attributeCommitments,
    TSS_DAA_ATTRIB_COMMIT* attributeCommitmentsProof,
    TSS_DAA_PSEUDONYM_PLAIN* pseudonym,
    TSS_DAA_PSEUDONYM_PLAIN* pseudonymTilde,
    TSS_DAA_PSEUDONYM_ENCRYPTED* pseudonymEncrypted,
    TSS_DAA_PSEUDONYM_ENCRYPTED* pseudonymEncProof,
    TSS_DAA_SIGN_CALLBACK** additionalProof
);

typedef TSS_RESULT (*Tspicb_DAA_VerifySignature)
(
    PVOID lpAppData,
    UINT32 challengeLength,
    BYTE* challenge,
    TSS_DAA_SIGN_CALLBACK* additionalProof,
    TSS_HDAA_ISSUER_KEY daaPublicKey,
    UINT32 gammasLength,
    BYTE** gammas,
    UINT32 sAttributesLength,
    BYTE** sAttributes,
    UINT32 attributeCommitmentsLength,
    TSS_DAA_ATTRIB_COMMIT* attributeCommitments,
    TSS_DAA_ATTRIB_COMMIT* attributeCommitmentsProof,
    UINT32 zetaLength,
    BYTE* zeta,
    UINT32 sFLength,
    BYTE* sF,
    TSS_DAA_PSEUDONYM* pseudonym,
    TSS_DAA_PSEUDONYM* pseudonymProof,
    TSS_BOOL* isCorrect
);

#define TSS_LEVEL_SUCCESS ...
#define TSS_LEVEL_INFO ...
#define TSS_LEVEL_WARNING ...
#define TSS_LEVEL_ERROR ...
#define FACILITY_TSS ...
#define FACILITY_TSS_CODEPOS ...
#define TSS_CUSTOM_CODEFLAG ...
#define TSS_E_BASE ...
#define TSS_W_BASE ...
#define TSS_I_BASE ...
#define TSS_SUCCESS ...
#define TSS_E_FAIL ...
#define TSS_E_BAD_PARAMETER ...
#define TSS_E_INTERNAL_ERROR ...
#define TSS_E_OUTOFMEMORY ...
#define TSS_E_NOTIMPL ...
#define TSS_E_KEY_ALREADY_REGISTERED ...
#define TSS_E_TPM_UNEXPECTED ...
#define TSS_E_COMM_FAILURE ...
#define TSS_E_TIMEOUT ...
#define TSS_E_TPM_UNSUPPORTED_FEATURE ...
#define TSS_E_CANCELED ...
#define TSS_E_PS_KEY_NOTFOUND ...
#define TSS_E_PS_KEY_EXISTS ...
#define TSS_E_PS_BAD_KEY_STATE ...
#define TSS_E_INVALID_OBJECT_TYPE ...
#define TSS_E_NO_CONNECTION ...
#define TSS_E_CONNECTION_FAILED ...
#define TSS_E_CONNECTION_BROKEN ...
#define TSS_E_HASH_INVALID_ALG ...
#define TSS_E_HASH_INVALID_LENGTH ...
#define TSS_E_HASH_NO_DATA ...
#define TSS_E_INVALID_ATTRIB_FLAG ...
#define TSS_E_INVALID_ATTRIB_SUBFLAG ...
#define TSS_E_INVALID_ATTRIB_DATA ...
#define TSS_E_INVALID_OBJECT_INIT_FLAG ...
#define TSS_E_INVALID_OBJECT_INITFLAG ...
#define TSS_E_NO_PCRS_SET ...
#define TSS_E_KEY_NOT_LOADED ...
#define TSS_E_KEY_NOT_SET ...
#define TSS_E_VALIDATION_FAILED ...
#define TSS_E_TSP_AUTHREQUIRED ...
#define TSS_E_TSP_AUTH2REQUIRED ...
#define TSS_E_TSP_AUTHFAIL ...
#define TSS_E_TSP_AUTH2FAIL ...
#define TSS_E_KEY_NO_MIGRATION_POLICY ...
#define TSS_E_POLICY_NO_SECRET ...
#define TSS_E_INVALID_OBJ_ACCESS ...
#define TSS_E_INVALID_ENCSCHEME ...
#define TSS_E_INVALID_SIGSCHEME ...
#define TSS_E_ENC_INVALID_LENGTH ...
#define TSS_E_ENC_NO_DATA ...
#define TSS_E_ENC_INVALID_TYPE ...
#define TSS_E_INVALID_KEYUSAGE ...
#define TSS_E_VERIFICATION_FAILED ...
#define TSS_E_HASH_NO_IDENTIFIER ...
#define TSS_E_INVALID_HANDLE ...
#define TSS_E_SILENT_CONTEXT ...
#define TSS_E_EK_CHECKSUM ...
#define TSS_E_DELEGATION_NOTSET ...
#define TSS_E_DELFAMILY_NOTFOUND ...
#define TSS_E_DELFAMILY_ROWEXISTS ...
#define TSS_E_VERSION_MISMATCH ...
#define TSS_E_DAA_AR_DECRYPTION_ERROR ...
#define TSS_E_DAA_AUTHENTICATION_ERROR ...
#define TSS_E_DAA_CHALLENGE_RESPONSE_ERROR ...
#define TSS_E_DAA_CREDENTIAL_PROOF_ERROR ...
#define TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR ...
#define TSS_E_DAA_ISSUER_KEY_ERROR ...
#define TSS_E_DAA_PSEUDONYM_ERROR ...
#define TSS_E_INVALID_RESOURCE ...
#define TSS_E_NV_AREA_EXIST ...
#define TSS_E_NV_AREA_NOT_EXIST ...
#define TSS_E_TSP_TRANS_AUTHFAIL ...
#define TSS_E_TSP_TRANS_AUTHREQUIRED ...
#define TSS_E_TSP_TRANS_NOTEXCLUSIVE ...
#define TSS_E_TSP_TRANS_FAIL ...
#define TSS_E_TSP_TRANS_NO_PUBKEY ...
#define TSS_E_NO_ACTIVE_COUNTER ...
#define TSS_OBJECT_TYPE_POLICY ...
#define TSS_OBJECT_TYPE_RSAKEY ...
#define TSS_OBJECT_TYPE_ENCDATA ...
#define TSS_OBJECT_TYPE_PCRS ...
#define TSS_OBJECT_TYPE_HASH ...
#define TSS_OBJECT_TYPE_DELFAMILY ...
#define TSS_OBJECT_TYPE_NV ...
#define TSS_OBJECT_TYPE_MIGDATA ...
#define TSS_OBJECT_TYPE_DAA_CERTIFICATE ...
#define TSS_OBJECT_TYPE_DAA_ISSUER_KEY ...
#define TSS_OBJECT_TYPE_DAA_ARA_KEY ...
#define TSS_KEY_NO_AUTHORIZATION ...
#define TSS_KEY_AUTHORIZATION ...
#define TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY ...
#define TSS_KEY_NON_VOLATILE ...
#define TSS_KEY_VOLATILE ...
#define TSS_KEY_NOT_MIGRATABLE ...
#define TSS_KEY_MIGRATABLE ...
#define TSS_KEY_TYPE_DEFAULT ...
#define TSS_KEY_TYPE_SIGNING ...
#define TSS_KEY_TYPE_STORAGE ...
#define TSS_KEY_TYPE_IDENTITY ...
#define TSS_KEY_TYPE_AUTHCHANGE ...
#define TSS_KEY_TYPE_BIND ...
#define TSS_KEY_TYPE_LEGACY ...
#define TSS_KEY_TYPE_MIGRATE ...
#define TSS_KEY_TYPE_BITMASK ...
#define TSS_KEY_SIZE_DEFAULT ...
#define TSS_KEY_SIZE_512 ...
#define TSS_KEY_SIZE_1024 ...
#define TSS_KEY_SIZE_2048 ...
#define TSS_KEY_SIZE_4096 ...
#define TSS_KEY_SIZE_8192 ...
#define TSS_KEY_SIZE_16384 ...
#define TSS_KEY_SIZE_BITMASK ...
#define TSS_KEY_NOT_CERTIFIED_MIGRATABLE ...
#define TSS_KEY_CERTIFIED_MIGRATABLE ...
#define TSS_KEY_STRUCT_DEFAULT ...
#define TSS_KEY_STRUCT_KEY ...
#define TSS_KEY_STRUCT_KEY12 ...
#define TSS_KEY_STRUCT_BITMASK ...
#define TSS_KEY_EMPTY_KEY ...
#define TSS_KEY_TSP_SRK ...
#define TSS_KEY_TEMPLATE_BITMASK ...
#define TSS_ENCDATA_SEAL ...
#define TSS_ENCDATA_BIND ...
#define TSS_ENCDATA_LEGACY ...
#define TSS_HASH_DEFAULT ...
#define TSS_HASH_SHA1 ...
#define TSS_HASH_OTHER ...
#define TSS_POLICY_USAGE ...
#define TSS_POLICY_MIGRATION ...
#define TSS_POLICY_OPERATOR ...
#define TSS_PCRS_STRUCT_DEFAULT ...
#define TSS_PCRS_STRUCT_INFO ...
#define TSS_PCRS_STRUCT_INFO_LONG ...
#define TSS_PCRS_STRUCT_INFO_SHORT ...
#define TSS_TSPATTRIB_CONTEXT_SILENT_MODE ...
#define TSS_TSPATTRIB_CONTEXT_MACHINE_NAME ...
#define TSS_TSPATTRIB_CONTEXT_VERSION_MODE ...
#define TSS_TSPATTRIB_CONTEXT_TRANSPORT ...
#define TSS_TSPATTRIB_CONTEXT_CONNECTION_VERSION ...
#define TSS_TSPATTRIB_SECRET_HASH_MODE ...
#define TSS_TSPATTRIB_CONTEXTTRANS_CONTROL ...
#define TSS_TSPATTRIB_CONTEXTTRANS_MODE ...
#define TSS_TSPATTRIB_CONTEXT_NOT_SILENT ...
#define TSS_TSPATTRIB_CONTEXT_SILENT ...
#define TSS_TSPATTRIB_CONTEXT_VERSION_AUTO ...
#define TSS_TSPATTRIB_CONTEXT_VERSION_V1_1 ...
#define TSS_TSPATTRIB_CONTEXT_VERSION_V1_2 ...
#define TSS_TSPATTRIB_DISABLE_TRANSPORT ...
#define TSS_TSPATTRIB_ENABLE_TRANSPORT ...
#define TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION ...
#define TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION ...
#define TSS_TSPATTRIB_TRANSPORT_AUTHENTIC_CHANNEL ...
#define TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE ...
#define TSS_TSPATTRIB_TRANSPORT_STATIC_AUTH ...
#define TSS_CONNECTION_VERSION_1_1 ...
#define TSS_CONNECTION_VERSION_1_2 ...
#define TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP ...
#define TSS_TSPATTRIB_HASH_MODE_NOT_NULL ...
#define TSS_TSPATTRIB_HASH_MODE_NULL ...
#define TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY ...
#define TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY ...
#define TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS ...
#define TSS_TSPATTRIB_TPM_CREDENTIAL ...
#define TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT ...
#define TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT ...
#define TSS_TPMATTRIB_EKCERT ...
#define TSS_TPMATTRIB_TPM_CC ...
#define TSS_TPMATTRIB_PLATFORMCERT ...
#define TSS_TPMATTRIB_PLATFORM_CC ...
#define TSS_TSPATTRIB_POLICY_CALLBACK_HMAC ...
#define TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC ...
#define TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP ...
#define TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM ...
#define TSS_TSPATTRIB_POLICY_SECRET_LIFETIME ...
#define TSS_TSPATTRIB_POLICY_POPUPSTRING ...
#define TSS_TSPATTRIB_POLICY_CALLBACK_SEALX_MASK ...
#define TSS_TSPATTRIB_SECRET_HASH_MODE ...
#define TSS_TSPATTRIB_POLICY_DELEGATION_INFO ...
#define TSS_TSPATTRIB_POLICY_DELEGATION_PCR ...
#define TSS_SECRET_LIFETIME_ALWAYS ...
#define TSS_SECRET_LIFETIME_COUNTER ...
#define TSS_SECRET_LIFETIME_TIMER ...
#define TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS ...
#define TSS_TSPATTRIB_POLSECRET_LIFETIME_COUNTER ...
#define TSS_TSPATTRIB_POLSECRET_LIFETIME_TIMER ...
#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS ...
#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER ...
#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER ...
#define TSS_TSPATTRIB_POLDEL_TYPE ...
#define TSS_TSPATTRIB_POLDEL_INDEX ...
#define TSS_TSPATTRIB_POLDEL_PER1 ...
#define TSS_TSPATTRIB_POLDEL_PER2 ...
#define TSS_TSPATTRIB_POLDEL_LABEL ...
#define TSS_TSPATTRIB_POLDEL_FAMILYID ...
#define TSS_TSPATTRIB_POLDEL_VERCOUNT ...
#define TSS_TSPATTRIB_POLDEL_OWNERBLOB ...
#define TSS_TSPATTRIB_POLDEL_KEYBLOB ...
#define TSS_TSPATTRIB_POLDELPCR_LOCALITY ...
#define TSS_TSPATTRIB_POLDELPCR_DIGESTATRELEASE ...
#define TSS_TSPATTRIB_POLDELPCR_SELECTION ...
#define TSS_DELEGATIONTYPE_NONE ...
#define TSS_DELEGATIONTYPE_OWNER ...
#define TSS_DELEGATIONTYPE_KEY ...
#define TSS_SECRET_MODE_NONE ...
#define TSS_SECRET_MODE_SHA1 ...
#define TSS_SECRET_MODE_PLAIN ...
#define TSS_SECRET_MODE_POPUP ...
#define TSS_SECRET_MODE_CALLBACK ...
#define TSS_TSPATTRIB_ENCDATA_BLOB ...
#define TSS_TSPATTRIB_ENCDATA_PCR ...
#define TSS_TSPATTRIB_ENCDATA_PCR_LONG ...
#define TSS_TSPATTRIB_ENCDATA_SEAL ...
#define TSS_TSPATTRIB_ENCDATABLOB_BLOB ...
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION ...
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATRELEASE ...
#define TSS_TSPATTRIB_ENCDATAPCR_SELECTION ...
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION ...
#define TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE ...
#define TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE ...
#define TSS_TSPATTRIB_ENCDATASEAL_NOPROTECT ...
#define TSS_TSPATTRIB_ENCDATASEAL_PROTECT ...
#define TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT ...
#define TSS_TSPATTRIB_NV_INDEX ...
#define TSS_TSPATTRIB_NV_PERMISSIONS ...
#define TSS_TSPATTRIB_NV_STATE ...
#define TSS_TSPATTRIB_NV_DATASIZE ...
#define TSS_TSPATTRIB_NV_PCR ...
#define TSS_TSPATTRIB_NVSTATE_READSTCLEAR ...
#define TSS_TSPATTRIB_NVSTATE_WRITESTCLEAR ...
#define TSS_TSPATTRIB_NVSTATE_WRITEDEFINE ...
#define TSS_TSPATTRIB_NVPCR_READPCRSELECTION ...
#define TSS_TSPATTRIB_NVPCR_READDIGESTATRELEASE ...
#define TSS_TSPATTRIB_NVPCR_READLOCALITYATRELEASE ...
#define TSS_TSPATTRIB_NVPCR_WRITEPCRSELECTION ...
#define TSS_TSPATTRIB_NVPCR_WRITEDIGESTATRELEASE ...
#define TSS_TSPATTRIB_NVPCR_WRITELOCALITYATRELEASE ...
#define TSS_NV_TPM ...
#define TSS_NV_PLATFORM ...
#define TSS_NV_USER ...
#define TSS_NV_DEFINED ...
#define TSS_NV_MASK_TPM ...
#define TSS_NV_MASK_PLATFORM ...
#define TSS_NV_MASK_USER ...
#define TSS_NV_MASK_DEFINED ...
#define TSS_NV_MASK_RESERVED ...
#define TSS_NV_MASK_PURVIEW ...
#define TSS_NV_MASK_INDEX ...
#define TSS_NV_INDEX_SESSIONS ...
#define TSS_MIGATTRIB_MIGRATIONBLOB ...
#define TSS_MIGATTRIB_MIGRATIONTICKET ...
#define TSS_MIGATTRIB_AUTHORITY_DATA ...
#define TSS_MIGATTRIB_MIG_AUTH_DATA ...
#define TSS_MIGATTRIB_TICKET_DATA ...
#define TSS_MIGATTRIB_PAYLOAD_TYPE ...
#define TSS_MIGATTRIB_MIGRATION_XOR_BLOB ...
#define TSS_MIGATTRIB_MIGRATION_REWRAPPED_BLOB ...
#define TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB ...
#define TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB ...
#define TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB ...
#define TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB ...
#define TSS_MIGATTRIB_MIG_REWRAPPED_BLOB ...
#define TSS_MIGATTRIB_MIG_XOR_BLOB ...
#define TSS_MIGATTRIB_AUTHORITY_DIGEST ...
#define TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC ...
#define TSS_MIGATTRIB_AUTHORITY_MSALIST ...
#define TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST ...
#define TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST ...
#define TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST ...
#define TSS_MIGATTRIB_TICKET_SIG_DIGEST ...
#define TSS_MIGATTRIB_TICKET_SIG_VALUE ...
#define TSS_MIGATTRIB_TICKET_SIG_TICKET ...
#define TSS_MIGATTRIB_TICKET_RESTRICT_TICKET ...
#define TSS_MIGATTRIB_PT_MIGRATE_RESTRICTED ...
#define TSS_MIGATTRIB_PT_MIGRATE_EXTERNAL ...
#define TSS_TSPATTRIB_HASH_IDENTIFIER ...
#define TSS_TSPATTRIB_ALG_IDENTIFIER ...
#define TSS_TSPATTRIB_PCRS_INFO ...
#define TSS_TSPATTRIB_PCRSINFO_PCRSTRUCT ...
#define TSS_TSPATTRIB_DELFAMILY_STATE ...
#define TSS_TSPATTRIB_DELFAMILY_INFO ...
#define TSS_TSPATTRIB_DELFAMILYSTATE_LOCKED ...
#define TSS_TSPATTRIB_DELFAMILYSTATE_ENABLED ...
#define TSS_TSPATTRIB_DELFAMILYINFO_LABEL ...
#define TSS_TSPATTRIB_DELFAMILYINFO_VERCOUNT ...
#define TSS_TSPATTRIB_DELFAMILYINFO_FAMILYID ...
#define TSS_DELEGATE_INCREMENTVERIFICATIONCOUNT ...
#define TSS_DELEGATE_CACHEOWNERDELEGATION_OVERWRITEEXISTING ...
#define TSS_TSPATTRIB_DAACRED_COMMIT ...
#define TSS_TSPATTRIB_DAACRED_ATTRIB_GAMMAS ...
#define TSS_TSPATTRIB_DAACRED_CREDENTIAL_BLOB ...
#define TSS_TSPATTRIB_DAACRED_CALLBACK_SIGN ...
#define TSS_TSPATTRIB_DAACRED_CALLBACK_VERIFYSIGNATURE ...
#define TSS_TSPATTRIB_DAACOMMIT_NUMBER ...
#define TSS_TSPATTRIB_DAACOMMIT_SELECTION ...
#define TSS_TSPATTRIB_DAACOMMIT_COMMITMENTS ...
#define TSS_TSPATTRIB_DAAATTRIBGAMMAS_BLOB ...
#define TSS_TSPATTRIB_DAAISSUERKEY_BLOB ...
#define TSS_TSPATTRIB_DAAISSUERKEY_PUBKEY ...
#define TSS_TSPATTRIB_DAAISSUERKEYBLOB_PUBLIC_KEY ...
#define TSS_TSPATTRIB_DAAISSUERKEYBLOB_SECRET_KEY ...
#define TSS_TSPATTRIB_DAAISSUERKEYBLOB_KEYBLOB ...
#define TSS_TSPATTRIB_DAAISSUERKEYBLOB_PROOF ...
#define TSS_TSPATTRIB_DAAISSUERKEYPUBKEY_NUM_ATTRIBS ...
#define TSS_TSPATTRIB_DAAISSUERKEYPUBKEY_NUM_PLATFORM_ATTRIBS ...
#define TSS_TSPATTRIB_DAAISSUERKEYPUBKEY_NUM_ISSUER_ATTRIBS ...
#define TSS_TSPATTRIB_DAAARAKEY_BLOB ...
#define TSS_TSPATTRIB_DAAARAKEYBLOB_PUBLIC_KEY ...
#define TSS_TSPATTRIB_DAAARAKEYBLOB_SECRET_KEY ...
#define TSS_TSPATTRIB_DAAARAKEYBLOB_KEYBLOB ...
#define TSS_FLAG_DAA_PSEUDONYM_PLAIN ...
#define TSS_FLAG_DAA_PSEUDONYM_ENCRYPTED ...
#define TSS_TSPATTRIB_KEY_BLOB ...
#define TSS_TSPATTRIB_KEY_INFO ...
#define TSS_TSPATTRIB_KEY_UUID ...
#define TSS_TSPATTRIB_KEY_PCR ...
#define TSS_TSPATTRIB_RSAKEY_INFO ...
#define TSS_TSPATTRIB_KEY_REGISTER ...
#define TSS_TSPATTRIB_KEY_PCR_LONG ...
#define TSS_TSPATTRIB_KEY_CONTROLBIT ...
#define TSS_TSPATTRIB_KEY_CMKINFO ...
#define TSS_TSPATTRIB_KEYBLOB_BLOB ...
#define TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY ...
#define TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY ...
#define TSS_TSPATTRIB_KEYINFO_SIZE ...
#define TSS_TSPATTRIB_KEYINFO_USAGE ...
#define TSS_TSPATTRIB_KEYINFO_KEYFLAGS ...
#define TSS_TSPATTRIB_KEYINFO_AUTHUSAGE ...
#define TSS_TSPATTRIB_KEYINFO_ALGORITHM ...
#define TSS_TSPATTRIB_KEYINFO_SIGSCHEME ...
#define TSS_TSPATTRIB_KEYINFO_ENCSCHEME ...
#define TSS_TSPATTRIB_KEYINFO_MIGRATABLE ...
#define TSS_TSPATTRIB_KEYINFO_REDIRECTED ...
#define TSS_TSPATTRIB_KEYINFO_VOLATILE ...
#define TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE ...
#define TSS_TSPATTRIB_KEYINFO_VERSION ...
#define TSS_TSPATTRIB_KEYINFO_CMK ...
#define TSS_TSPATTRIB_KEYINFO_KEYSTRUCT ...
#define TSS_TSPATTRIB_KEYCONTROL_OWNEREVICT ...
#define TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT ...
#define TSS_TSPATTRIB_KEYINFO_RSA_MODULUS ...
#define TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE ...
#define TSS_TSPATTRIB_KEYINFO_RSA_PRIMES ...
#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION ...
#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE ...
#define TSS_TSPATTRIB_KEYPCR_SELECTION ...
#define TSS_TSPATTRIB_KEYREGISTER_USER ...
#define TSS_TSPATTRIB_KEYREGISTER_SYSTEM ...
#define TSS_TSPATTRIB_KEYREGISTER_NO ...
#define TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION ...
#define TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE ...
#define TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION ...
#define TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION ...
#define TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION ...
#define TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE ...
#define TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL ...
#define TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST ...
#define TSS_KEY_SIZEVAL_512BIT ...
#define TSS_KEY_SIZEVAL_1024BIT ...
#define TSS_KEY_SIZEVAL_2048BIT ...
#define TSS_KEY_SIZEVAL_4096BIT ...
#define TSS_KEY_SIZEVAL_8192BIT ...
#define TSS_KEY_SIZEVAL_16384BIT ...
#define TSS_KEYUSAGE_BIND ...
#define TSS_KEYUSAGE_IDENTITY ...
#define TSS_KEYUSAGE_LEGACY ...
#define TSS_KEYUSAGE_SIGN ...
#define TSS_KEYUSAGE_STORAGE ...
#define TSS_KEYUSAGE_AUTHCHANGE ...
#define TSS_KEYUSAGE_MIGRATE ...
#define TSS_KEYFLAG_REDIRECTION ...
#define TSS_KEYFLAG_MIGRATABLE ...
#define TSS_KEYFLAG_VOLATILEKEY ...
#define TSS_KEYFLAG_CERTIFIED_MIGRATABLE ...
#define TSS_ALG_RSA ...
#define TSS_ALG_DES ...
#define TSS_ALG_3DES ...
#define TSS_ALG_SHA ...
#define TSS_ALG_HMAC ...
#define TSS_ALG_AES128 ...
#define TSS_ALG_AES192 ...
#define TSS_ALG_AES256 ...
#define TSS_ALG_XOR ...
#define TSS_ALG_MGF1 ...
#define TSS_ALG_AES ...
#define TSS_ALG_DEFAULT ...
#define TSS_ALG_DEFAULT_SIZE ...
#define TSS_SS_NONE ...
#define TSS_SS_RSASSAPKCS1V15_SHA1 ...
#define TSS_SS_RSASSAPKCS1V15_DER ...
#define TSS_SS_RSASSAPKCS1V15_INFO ...
#define TSS_ES_NONE ...
#define TSS_ES_RSAESPKCSV15 ...
#define TSS_ES_RSAESOAEP_SHA1_MGF1 ...
#define TSS_ES_SYM_CNT ...
#define TSS_ES_SYM_OFB ...
#define TSS_ES_SYM_CBC_PKCS5PAD ...
#define TSS_PS_TYPE_USER ...
#define TSS_PS_TYPE_SYSTEM ...
#define TSS_MS_MIGRATE ...
#define TSS_MS_REWRAP ...
#define TSS_MS_MAINT ...
#define TSS_MS_RESTRICT_MIGRATE ...
#define TSS_MS_RESTRICT_APPROVE_DOUBLE ...
#define TSS_MS_RESTRICT_MIGRATE_EXTERNAL ...
#define TSS_KEYAUTH_AUTH_NEVER ...
#define TSS_KEYAUTH_AUTH_ALWAYS ...
#define TSS_KEYAUTH_AUTH_PRIV_USE_ONLY ...
#define TSS_TPMSTATUS_DISABLEOWNERCLEAR ...
#define TSS_TPMSTATUS_DISABLEFORCECLEAR ...
#define TSS_TPMSTATUS_DISABLED ...
#define TSS_TPMSTATUS_DEACTIVATED ...
#define TSS_TPMSTATUS_OWNERSETDISABLE ...
#define TSS_TPMSTATUS_SETOWNERINSTALL ...
#define TSS_TPMSTATUS_DISABLEPUBEKREAD ...
#define TSS_TPMSTATUS_ALLOWMAINTENANCE ...
#define TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK ...
#define TSS_TPMSTATUS_PHYSPRES_HWENABLE ...
#define TSS_TPMSTATUS_PHYSPRES_CMDENABLE ...
#define TSS_TPMSTATUS_PHYSPRES_LOCK ...
#define TSS_TPMSTATUS_PHYSPRESENCE ...
#define TSS_TPMSTATUS_PHYSICALDISABLE ...
#define TSS_TPMSTATUS_CEKP_USED ...
#define TSS_TPMSTATUS_PHYSICALSETDEACTIVATED ...
#define TSS_TPMSTATUS_SETTEMPDEACTIVATED ...
#define TSS_TPMSTATUS_POSTINITIALISE ...
#define TSS_TPMSTATUS_TPMPOST ...
#define TSS_TPMSTATUS_TPMPOSTLOCK ...
#define TSS_TPMSTATUS_DISABLEPUBSRKREAD ...
#define TSS_TPMSTATUS_MAINTENANCEUSED ...
#define TSS_TPMSTATUS_OPERATORINSTALLED ...
#define TSS_TPMSTATUS_OPERATOR_INSTALLED ...
#define TSS_TPMSTATUS_FIPS ...
#define TSS_TPMSTATUS_ENABLEREVOKEEK ...
#define TSS_TPMSTATUS_ENABLE_REVOKEEK ...
#define TSS_TPMSTATUS_NV_LOCK ...
#define TSS_TPMSTATUS_TPM_ESTABLISHED ...
#define TSS_TPMSTATUS_RESETLOCK ...
#define TSS_TPMSTATUS_DISABLE_FULL_DA_LOGIC_INFO ...
#define TSS_TPMCAP_ORD ...
#define TSS_TPMCAP_ALG ...
#define TSS_TPMCAP_FLAG ...
#define TSS_TPMCAP_PROPERTY ...
#define TSS_TPMCAP_VERSION ...
#define TSS_TPMCAP_VERSION_VAL ...
#define TSS_TPMCAP_NV_LIST ...
#define TSS_TPMCAP_NV_INDEX ...
#define TSS_TPMCAP_MFR ...
#define TSS_TPMCAP_SYM_MODE ...
#define TSS_TPMCAP_HANDLE ...
#define TSS_TPMCAP_TRANS_ES ...
#define TSS_TPMCAP_AUTH_ENCRYPT ...
#define TSS_TPMCAP_SET_PERM_FLAGS ...
#define TSS_TPMCAP_SET_VENDOR ...
#define TSS_TPMCAP_DA_LOGIC ...
#define TSS_TPMCAP_PROP_PCR ...
#define TSS_TPMCAP_PROP_DIR ...
#define TSS_TPMCAP_PROP_MANUFACTURER ...
#define TSS_TPMCAP_PROP_SLOTS ...
#define TSS_TPMCAP_PROP_KEYS ...
#define TSS_TPMCAP_PROP_FAMILYROWS ...
#define TSS_TPMCAP_PROP_DELEGATEROWS ...
#define TSS_TPMCAP_PROP_OWNER ...
#define TSS_TPMCAP_PROP_MAXKEYS ...
#define TSS_TPMCAP_PROP_AUTHSESSIONS ...
#define TSS_TPMCAP_PROP_MAXAUTHSESSIONS ...
#define TSS_TPMCAP_PROP_TRANSESSIONS ...
#define TSS_TPMCAP_PROP_MAXTRANSESSIONS ...
#define TSS_TPMCAP_PROP_SESSIONS ...
#define TSS_TPMCAP_PROP_MAXSESSIONS ...
#define TSS_TPMCAP_PROP_CONTEXTS ...
#define TSS_TPMCAP_PROP_MAXCONTEXTS ...
#define TSS_TPMCAP_PROP_DAASESSIONS ...
#define TSS_TPMCAP_PROP_MAXDAASESSIONS ...
#define TSS_TPMCAP_PROP_DAA_INTERRUPT ...
#define TSS_TPMCAP_PROP_COUNTERS ...
#define TSS_TPMCAP_PROP_MAXCOUNTERS ...
#define TSS_TPMCAP_PROP_ACTIVECOUNTER ...
#define TSS_TPMCAP_PROP_MIN_COUNTER ...
#define TSS_TPMCAP_PROP_TISTIMEOUTS ...
#define TSS_TPMCAP_PROP_STARTUPEFFECTS ...
#define TSS_TPMCAP_PROP_MAXCONTEXTCOUNTDIST ...
#define TSS_TPMCAP_PROP_CMKRESTRICTION ...
#define TSS_TPMCAP_PROP_DURATION ...
#define TSS_TPMCAP_PROP_MAXNVAVAILABLE ...
#define TSS_TPMCAP_PROP_INPUTBUFFERSIZE ...
#define TSS_TPMCAP_PROP_REVISION ...
#define TSS_TPMCAP_PROP_LOCALITIES_AVAIL ...
#define TSS_RT_KEY ...
#define TSS_RT_AUTH ...
#define TSS_RT_TRANS ...
#define TSS_RT_COUNTER ...
#define TSS_TCSCAP_ALG ...
#define TSS_TCSCAP_VERSION ...
#define TSS_TCSCAP_CACHING ...
#define TSS_TCSCAP_PERSSTORAGE ...
#define TSS_TCSCAP_MANUFACTURER ...
#define TSS_TCSCAP_PLATFORM_CLASS ...
#define TSS_TCSCAP_TRANSPORT ...
#define TSS_TCSCAP_PLATFORM_INFO ...
#define TSS_TCSCAP_PROP_KEYCACHE ...
#define TSS_TCSCAP_PROP_AUTHCACHE ...
#define TSS_TCSCAP_PROP_MANUFACTURER_STR ...
#define TSS_TCSCAP_PROP_MANUFACTURER_ID ...
#define TSS_TCSCAP_PLATFORM_VERSION ...
#define TSS_TCSCAP_PLATFORM_TYPE ...
#define TSS_TCSCAP_TRANS_EXCLUSIVE ...
#define TSS_TCSCAP_PROP_HOST_PLATFORM ...
#define TSS_TCSCAP_PROP_ALL_PLATFORMS ...
#define TSS_TSPCAP_ALG ...
#define TSS_TSPCAP_VERSION ...
#define TSS_TSPCAP_PERSSTORAGE ...
#define TSS_TSPCAP_MANUFACTURER ...
#define TSS_TSPCAP_RETURNVALUE_INFO ...
#define TSS_TSPCAP_PLATFORM_INFO ...
#define TSS_TSPCAP_PROP_MANUFACTURER_STR ...
#define TSS_TSPCAP_PROP_MANUFACTURER_ID ...
#define TSS_TSPCAP_PLATFORM_TYPE ...
#define TSS_TSPCAP_PLATFORM_VERSION ...
#define TSS_TSPCAP_PROP_RETURNVALUE_INFO ...
#define TSS_EV_CODE_CERT ...
#define TSS_EV_CODE_NOCERT ...
#define TSS_EV_XML_CONFIG ...
#define TSS_EV_NO_ACTION ...
#define TSS_EV_SEPARATOR ...
#define TSS_EV_ACTION ...
#define TSS_EV_PLATFORM_SPECIFIC ...
#define TSS_TSPCAP_RANDOMLIMIT ...
#define TSS_PCRS_DIRECTION_CREATION ...
#define TSS_PCRS_DIRECTION_RELEASE ...
#define TSS_BLOB_STRUCT_VERSION ...
#define TSS_BLOB_TYPE_KEY ...
#define TSS_BLOB_TYPE_PUBKEY ...
#define TSS_BLOB_TYPE_MIGKEY ...
#define TSS_BLOB_TYPE_SEALEDDATA ...
#define TSS_BLOB_TYPE_BOUNDDATA ...
#define TSS_BLOB_TYPE_MIGTICKET ...
#define TSS_BLOB_TYPE_PRIVATEKEY ...
#define TSS_BLOB_TYPE_PRIVATEKEY_MOD1 ...
#define TSS_BLOB_TYPE_RANDOM_XOR ...
#define TSS_BLOB_TYPE_CERTIFY_INFO ...
#define TSS_BLOB_TYPE_KEY_1_2 ...
#define TSS_BLOB_TYPE_CERTIFY_INFO_2 ...
#define TSS_BLOB_TYPE_CMK_MIG_KEY ...
#define TSS_BLOB_TYPE_CMK_BYTE_STREAM ...
#define TSS_CMK_DELEGATE_SIGNING ...
#define TSS_CMK_DELEGATE_STORAGE ...
#define TSS_CMK_DELEGATE_BIND ...
#define TSS_CMK_DELEGATE_LEGACY ...
#define TSS_CMK_DELEGATE_MIGRATE ...
#define TSS_DAA_LENGTH_N ...
#define TSS_DAA_LENGTH_F ...
#define TSS_DAA_LENGTH_E ...
#define TSS_DAA_LENGTH_E_PRIME ...
#define TSS_DAA_LENGTH_V ...
#define TSS_DAA_LENGTH_SAFETY ...
#define TSS_DAA_LENGTH_HASH ...
#define TSS_DAA_LENGTH_S ...
#define TSS_DAA_LENGTH_GAMMA ...
#define TSS_DAA_LENGTH_RHO ...
#define TSS_DAA_LENGTH_MFG1_GAMMA ...
#define TSS_DAA_LENGTH_MGF1_AR ...
#define TPM_Vendor_Specific32 ...
#define TPM_Vendor_Specific8 ...
#define TPM_TAG_CONTEXTBLOB ...
#define TPM_TAG_CONTEXT_SENSITIVE ...
#define TPM_TAG_CONTEXTPOINTER ...
#define TPM_TAG_CONTEXTLIST ...
#define TPM_TAG_SIGNINFO ...
#define TPM_TAG_PCR_INFO_LONG ...
#define TPM_TAG_PERSISTENT_FLAGS ...
#define TPM_TAG_VOLATILE_FLAGS ...
#define TPM_TAG_PERSISTENT_DATA ...
#define TPM_TAG_VOLATILE_DATA ...
#define TPM_TAG_SV_DATA ...
#define TPM_TAG_EK_BLOB ...
#define TPM_TAG_EK_BLOB_AUTH ...
#define TPM_TAG_COUNTER_VALUE ...
#define TPM_TAG_TRANSPORT_INTERNAL ...
#define TPM_TAG_TRANSPORT_LOG_IN ...
#define TPM_TAG_TRANSPORT_LOG_OUT ...
#define TPM_TAG_AUDIT_EVENT_IN ...
#define TPM_TAG_AUDIT_EVENT_OUT ...
#define TPM_TAG_CURRENT_TICKS ...
#define TPM_TAG_KEY ...
#define TPM_TAG_STORED_DATA12 ...
#define TPM_TAG_NV_ATTRIBUTES ...
#define TPM_TAG_NV_DATA_PUBLIC ...
#define TPM_TAG_NV_DATA_SENSITIVE ...
#define TPM_TAG_DELEGATIONS ...
#define TPM_TAG_DELEGATE_PUBLIC ...
#define TPM_TAG_DELEGATE_TABLE_ROW ...
#define TPM_TAG_TRANSPORT_AUTH ...
#define TPM_TAG_TRANSPORT_PUBLIC ...
#define TPM_TAG_PERMANENT_FLAGS ...
#define TPM_TAG_STCLEAR_FLAGS ...
#define TPM_TAG_STANY_FLAGS ...
#define TPM_TAG_PERMANENT_DATA ...
#define TPM_TAG_STCLEAR_DATA ...
#define TPM_TAG_STANY_DATA ...
#define TPM_TAG_FAMILY_TABLE_ENTRY ...
#define TPM_TAG_DELEGATE_SENSITIVE ...
#define TPM_TAG_DELG_KEY_BLOB ...
#define TPM_TAG_KEY12 ...
#define TPM_TAG_CERTIFY_INFO2 ...
#define TPM_TAG_DELEGATE_OWNER_BLOB ...
#define TPM_TAG_EK_BLOB_ACTIVATE ...
#define TPM_TAG_DAA_BLOB ...
#define TPM_TAG_DAA_CONTEXT ...
#define TPM_TAG_DAA_ENFORCE ...
#define TPM_TAG_DAA_ISSUER ...
#define TPM_TAG_CAP_VERSION_INFO ...
#define TPM_TAG_DAA_SENSITIVE ...
#define TPM_TAG_DAA_TPM ...
#define TPM_TAG_CMK_MIGAUTH ...
#define TPM_TAG_CMK_SIGTICKET ...
#define TPM_TAG_CMK_MA_APPROVAL ...
#define TPM_TAG_QUOTE_INFO2 ...
#define TPM_TAG_DA_INFO ...
#define TPM_TAG_DA_INFO_LIMITED ...
#define TPM_TAG_DA_ACTION_TYPE ...
#define TPM_RT_KEY ...
#define TPM_RT_AUTH ...
#define TPM_RT_HASH ...
#define TPM_RT_TRANS ...
#define TPM_RT_CONTEXT ...
#define TPM_RT_COUNTER ...
#define TPM_RT_DELEGATE ...
#define TPM_RT_DAA_TPM ...
#define TPM_RT_DAA_V0 ...
#define TPM_RT_DAA_V1 ...
#define TPM_PT_ASYM ...
#define TPM_PT_BIND ...
#define TPM_PT_MIGRATE ...
#define TPM_PT_MAINT ...
#define TPM_PT_SEAL ...
#define TPM_PT_MIGRATE_RESTRICTED ...
#define TPM_PT_MIGRATE_EXTERNAL ...
#define TPM_PT_CMK_MIGRATE ...
#define TPM_ET_KEYHANDLE ...
#define TPM_ET_OWNER ...
#define TPM_ET_DATA ...
#define TPM_ET_SRK ...
#define TPM_ET_KEY ...
#define TPM_ET_REVOKE ...
#define TPM_ET_DEL_OWNER_BLOB ...
#define TPM_ET_DEL_ROW ...
#define TPM_ET_DEL_KEY_BLOB ...
#define TPM_ET_COUNTER ...
#define TPM_ET_NV ...
#define TPM_ET_OPERATOR ...
#define TPM_ET_RESERVED_HANDLE ...
#define TPM_ET_XOR ...
#define TPM_ET_AES ...
#define TPM_KH_SRK ...
#define TPM_KH_OWNER ...
#define TPM_KH_REVOKE ...
#define TPM_KH_TRANSPORT ...
#define TPM_KH_OPERATOR ...
#define TPM_KH_ADMIN ...
#define TPM_KH_EK ...
#define TPM_KEYHND_SRK ...
#define TPM_KEYHND_OWNER ...
#define TPM_ST_CLEAR ...
#define TPM_ST_STATE ...
#define TPM_ST_DEACTIVATED ...
#define TPM_PID_OIAP ...
#define TPM_PID_OSAP ...
#define TPM_PID_ADIP ...
#define TPM_PID_ADCP ...
#define TPM_PID_OWNER ...
#define TPM_PID_DSAP ...
#define TPM_PID_TRANSPORT ...
#define TPM_ALG_RSA ...
#define TPM_ALG_DES ...
#define TPM_ALG_3DES ...
#define TPM_ALG_SHA ...
#define TPM_ALG_HMAC ...
#define TPM_ALG_AES ...
#define TPM_ALG_AES128 ...
#define TPM_ALG_MGF1 ...
#define TPM_ALG_AES192 ...
#define TPM_ALG_AES256 ...
#define TPM_ALG_XOR ...
#define TPM_PHYSICAL_PRESENCE_LOCK ...
#define TPM_PHYSICAL_PRESENCE_PRESENT ...
#define TPM_PHYSICAL_PRESENCE_NOTPRESENT ...
#define TPM_PHYSICAL_PRESENCE_CMD_ENABLE ...
#define TPM_PHYSICAL_PRESENCE_HW_ENABLE ...
#define TPM_PHYSICAL_PRESENCE_LIFETIME_LOCK ...
#define TPM_PHYSICAL_PRESENCE_CMD_DISABLE ...
#define TPM_PHYSICAL_PRESENCE_HW_DISABLE ...
#define TPM_MS_MIGRATE ...
#define TPM_MS_REWRAP ...
#define TPM_MS_MAINT ...
#define TPM_MS_RESTRICT_MIGRATE ...
#define TPM_MS_RESTRICT_APPROVE_DOUBLE ...
#define TPM_EK_TYPE_ACTIVATE ...
#define TPM_EK_TYPE_AUTH ...
#define TPM_PS_PC_11 ...
#define TPM_PS_PC_12 ...
#define TPM_PS_PDA_12 ...
#define TPM_PS_Server_12 ...
#define TPM_PS_Mobile_12 ...
#define TPM_SHA1_160_HASH_LEN ...
#define TPM_SHA1BASED_NONCE_LEN ...
#define TPM_KEY_SIGNING ...
#define TPM_KEY_STORAGE ...
#define TPM_KEY_IDENTITY ...
#define TPM_KEY_AUTHCHANGE ...
#define TPM_KEY_BIND ...
#define TPM_KEY_LEGACY ...
#define TPM_KEY_MIGRATE ...
#define TPM_SS_NONE ...
#define TPM_SS_RSASSAPKCS1v15_SHA1 ...
#define TPM_SS_RSASSAPKCS1v15_DER ...
#define TPM_SS_RSASSAPKCS1v15_INFO ...
#define TPM_ES_NONE ...
#define TPM_ES_RSAESPKCSv15 ...
#define TPM_ES_RSAESOAEP_SHA1_MGF1 ...
#define TPM_ES_SYM_CNT ...
#define TPM_ES_SYM_CTR ...
#define TPM_ES_SYM_OFB ...
#define TPM_ES_SYM_CBC_PKCS5PAD ...
#define TPM_AUTH_NEVER ...
#define TPM_AUTH_ALWAYS ...
#define TPM_AUTH_PRIV_USE_ONLY ...
#define TPM_REDIRECTION ...
#define TPM_MIGRATABLE ...
#define TPM_VOLATILE ...
#define TPM_PCRIGNOREDONREAD ...
#define TPM_MIGRATEAUTHORITY ...
#define TPM_CMK_DELEGATE_SIGNING ...
#define TPM_CMK_DELEGATE_STORAGE ...
#define TPM_CMK_DELEGATE_BIND ...
#define TPM_CMK_DELEGATE_LEGACY ...
#define TPM_CMK_DELEGATE_MIGRATE ...
#define TPM_TAG_RQU_COMMAND ...
#define TPM_TAG_RQU_AUTH1_COMMAND ...
#define TPM_TAG_RQU_AUTH2_COMMAND ...
#define TPM_TAG_RSP_COMMAND ...
#define TPM_TAG_RSP_AUTH1_COMMAND ...
#define TPM_TAG_RSP_AUTH2_COMMAND ...
#define TPM_PF_DISABLE ...
#define TPM_PF_OWNERSHIP ...
#define TPM_PF_DEACTIVATED ...
#define TPM_PF_READPUBEK ...
#define TPM_PF_DISABLEOWNERCLEAR ...
#define TPM_PF_ALLOWMAINTENANCE ...
#define TPM_PF_PHYSICALPRESENCELIFETIMELOCK ...
#define TPM_PF_PHYSICALPRESENCEHWENABLE ...
#define TPM_PF_PHYSICALPRESENCECMDENABLE ...
#define TPM_PF_CEKPUSED ...
#define TPM_PF_TPMPOST ...
#define TPM_PF_TPMPOSTLOCK ...
#define TPM_PF_FIPS ...
#define TPM_PF_OPERATOR ...
#define TPM_PF_ENABLEREVOKEEK ...
#define TPM_PF_NV_LOCKED ...
#define TPM_PF_READSRKPUB ...
#define TPM_PF_RESETESTABLISHMENTBIT ...
#define TPM_PF_MAINTENANCEDONE ...
#define TPM_PF_DISABLEFULLDALOGICINFO ...
#define TPM_SF_DEACTIVATED ...
#define TPM_SF_DISABLEFORCECLEAR ...
#define TPM_SF_PHYSICALPRESENCE ...
#define TPM_SF_PHYSICALPRESENCELOCK ...
#define TPM_SF_GLOBALLOCK ...
#define TPM_AF_POSTINITIALIZE ...
#define TPM_AF_LOCALITYMODIFIER ...
#define TPM_AF_TRANSPORTEXCLUSIVE ...
#define TPM_AF_TOSPRESENT ...
//#define TPM_MIN_COUNTERS ...
//#define TPM_NUM_PCR ...
//#define TPM_MAX_NV_WRITE_NOOWNER ...
#define TPM_LOC_FOUR ...
#define TPM_LOC_THREE ...
#define TPM_LOC_TWO ...
#define TPM_LOC_ONE ...
#define TPM_LOC_ZERO ...
#define TPM_KEY_CONTROL_OWNER_EVICT ...
#define TPM_TRANSPORT_ENCRYPT ...
#define TPM_TRANSPORT_LOG ...
#define TPM_TRANSPORT_EXCLUSIVE ...
#define TPM_NV_INDEX_LOCK ...
#define TPM_NV_INDEX0 ...
#define TPM_NV_INDEX_DIR ...
#define TPM_NV_INDEX_EKCert ...
#define TPM_NV_INDEX_TPM_CC ...
#define TPM_NV_INDEX_PlatformCert ...
#define TPM_NV_INDEX_Platform_CC ...
#define TPM_NV_INDEX_TSS_BASE ...
#define TPM_NV_INDEX_PC_BASE ...
#define TPM_NV_INDEX_SERVER_BASE ...
#define TPM_NV_INDEX_MOBILE_BASE ...
#define TPM_NV_INDEX_PERIPHERAL_BASE ...
#define TPM_NV_INDEX_GROUP_RESV_BASE ...
#define TPM_NV_PER_READ_STCLEAR ...
#define TPM_NV_PER_AUTHREAD ...
#define TPM_NV_PER_OWNERREAD ...
#define TPM_NV_PER_PPREAD ...
#define TPM_NV_PER_GLOBALLOCK ...
#define TPM_NV_PER_WRITE_STCLEAR ...
#define TPM_NV_PER_WRITEDEFINE ...
#define TPM_NV_PER_WRITEALL ...
#define TPM_NV_PER_AUTHWRITE ...
#define TPM_NV_PER_OWNERWRITE ...
#define TPM_NV_PER_PPWRITE ...
#define TPM_DELEGATE_SetOrdinalAuditStatus ...
#define TPM_DELEGATE_DirWriteAuth ...
#define TPM_DELEGATE_CMK_ApproveMA ...
#define TPM_DELEGATE_NV_WriteValue ...
#define TPM_DELEGATE_CMK_CreateTicket ...
#define TPM_DELEGATE_NV_ReadValue ...
#define TPM_DELEGATE_Delegate_LoadOwnerDelegation ...
#define TPM_DELEGATE_DAA_Join ...
#define TPM_DELEGATE_AuthorizeMigrationKey ...
#define TPM_DELEGATE_CreateMaintenanceArchive ...
#define TPM_DELEGATE_LoadMaintenanceArchive ...
#define TPM_DELEGATE_KillMaintenanceFeature ...
#define TPM_DELEGATE_OwnerReadInternalPub ...
#define TPM_DELEGATE_ResetLockValue ...
#define TPM_DELEGATE_OwnerClear ...
#define TPM_DELEGATE_DisableOwnerClear ...
#define TPM_DELEGATE_NV_DefineSpace ...
#define TPM_DELEGATE_OwnerSetDisable ...
#define TPM_DELEGATE_SetCapability ...
#define TPM_DELEGATE_MakeIdentity ...
#define TPM_DELEGATE_ActivateIdentity ...
#define TPM_DELEGATE_OwnerReadPubek ...
#define TPM_DELEGATE_DisablePubekRead ...
#define TPM_DELEGATE_SetRedirection ...
#define TPM_DELEGATE_FieldUpgrade ...
#define TPM_DELEGATE_Delegate_UpdateVerification ...
#define TPM_DELEGATE_CreateCounter ...
#define TPM_DELEGATE_ReleaseCounterOwner ...
#define TPM_DELEGATE_DelegateManage ...
#define TPM_DELEGATE_Delegate_CreateOwnerDelegation ...
#define TPM_DELEGATE_DAA_Sign ...
#define TPM_KEY_DELEGATE_CMK_ConvertMigration ...
#define TPM_KEY_DELEGATE_TickStampBlob ...
#define TPM_KEY_DELEGATE_ChangeAuthAsymStart ...
#define TPM_KEY_DELEGATE_ChangeAuthAsymFinish ...
#define TPM_KEY_DELEGATE_CMK_CreateKey ...
#define TPM_KEY_DELEGATE_MigrateKey ...
#define TPM_KEY_DELEGATE_LoadKey2 ...
#define TPM_KEY_DELEGATE_EstablishTransport ...
#define TPM_KEY_DELEGATE_ReleaseTransportSigned ...
#define TPM_KEY_DELEGATE_Quote2 ...
#define TPM_KEY_DELEGATE_Sealx ...
#define TPM_KEY_DELEGATE_MakeIdentity ...
#define TPM_KEY_DELEGATE_ActivateIdentity ...
#define TPM_KEY_DELEGATE_GetAuditDigestSigned ...
#define TPM_KEY_DELEGATE_Sign ...
#define TPM_KEY_DELEGATE_CertifyKey2 ...
#define TPM_KEY_DELEGATE_CertifyKey ...
#define TPM_KEY_DELEGATE_CreateWrapKey ...
#define TPM_KEY_DELEGATE_CMK_CreateBlob ...
#define TPM_KEY_DELEGATE_CreateMigrationBlob ...
#define TPM_KEY_DELEGATE_ConvertMigrationBlob ...
#define TPM_KEY_DELEGATE_CreateKeyDelegation ...
#define TPM_KEY_DELEGATE_ChangeAuth ...
#define TPM_KEY_DELEGATE_GetPubKey ...
#define TPM_KEY_DELEGATE_UnBind ...
#define TPM_KEY_DELEGATE_Quote ...
#define TPM_KEY_DELEGATE_Unseal ...
#define TPM_KEY_DELEGATE_Seal ...
#define TPM_KEY_DELEGATE_LoadKey ...
#define TPM_FAMILY_CREATE ...
#define TPM_FAMILY_ENABLE ...
#define TPM_FAMILY_ADMIN ...
#define TPM_FAMILY_INVALIDATE ...
#define TPM_FAMFLAG_DELEGATE_ADMIN_LOCK ...
#define TPM_FAMFLAG_ENABLE ...
#define TPM_FAMILY_TABLE_ENTRY_MIN ...
#define TPM_DEL_OWNER_BITS ...
#define TPM_DEL_KEY_BITS ...
#define TPM_NUM_DELEGATE_TABLE_ENTRY_MIN ...
#define TPM_CAP_ORD ...
#define TPM_CAP_ALG ...
#define TPM_CAP_PID ...
#define TPM_CAP_FLAG ...
#define TPM_CAP_PROPERTY ...
#define TPM_CAP_VERSION ...
#define TPM_CAP_KEY_HANDLE ...
#define TPM_CAP_CHECK_LOADED ...
#define TPM_CAP_SYM_MODE ...
#define TPM_CAP_KEY_STATUS ...
#define TPM_CAP_NV_LIST ...
#define TPM_CAP_MFR ...
#define TPM_CAP_NV_INDEX ...
#define TPM_CAP_TRANS_ALG ...
#define TPM_CAP_HANDLE ...
#define TPM_CAP_TRANS_ES ...
#define TPM_CAP_AUTH_ENCRYPT ...
#define TPM_CAP_SELECT_SIZE ...
#define TPM_CAP_DA_LOGIC ...
#define TPM_CAP_VERSION_VAL ...
#define TPM_CAP_FLAG_PERMANENT ...
#define TPM_CAP_FLAG_VOLATILE ...
#define TPM_CAP_PROP_PCR ...
#define TPM_CAP_PROP_DIR ...
#define TPM_CAP_PROP_MANUFACTURER ...
#define TPM_CAP_PROP_KEYS ...
#define TPM_CAP_PROP_SLOTS ...
#define TPM_CAP_PROP_MIN_COUNTER ...
#define TPM_CAP_PROP_AUTHSESS ...
#define TPM_CAP_PROP_TRANSSESS ...
#define TPM_CAP_PROP_COUNTERS ...
#define TPM_CAP_PROP_MAX_AUTHSESS ...
#define TPM_CAP_PROP_MAX_TRANSSESS ...
#define TPM_CAP_PROP_MAX_COUNTERS ...
#define TPM_CAP_PROP_MAX_KEYS ...
#define TPM_CAP_PROP_OWNER ...
#define TPM_CAP_PROP_CONTEXT ...
#define TPM_CAP_PROP_MAX_CONTEXT ...
#define TPM_CAP_PROP_FAMILYROWS ...
#define TPM_CAP_PROP_TIS_TIMEOUT ...
#define TPM_CAP_PROP_STARTUP_EFFECT ...
#define TPM_CAP_PROP_DELEGATE_ROW ...
#define TPM_CAP_PROP_MAX_DAASESS ...
#define TPM_CAP_PROP_DAA_MAX ...
#define TPM_CAP_PROP_DAASESS ...
#define TPM_CAP_PROP_SESSION_DAA ...
#define TPM_CAP_PROP_CONTEXT_DIST ...
#define TPM_CAP_PROP_DAA_INTERRUPT ...
#define TPM_CAP_PROP_SESSIONS ...
#define TPM_CAP_PROP_MAX_SESSIONS ...
#define TPM_CAP_PROP_CMK_RESTRICTION ...
#define TPM_CAP_PROP_DURATION ...
#define TPM_CAP_PROP_ACTIVE_COUNTER ...
#define TPM_CAP_PROP_NV_AVAILABLE ...
#define TPM_CAP_PROP_INPUT_BUFFER ...
#define TPM_SET_PERM_FLAGS ...
#define TPM_SET_PERM_DATA ...
#define TPM_SET_STCLEAR_FLAGS ...
#define TPM_SET_STCLEAR_DATA ...
#define TPM_SET_STANY_FLAGS ...
#define TPM_SET_STANY_DATA ...
#define TPM_SET_VENDOR ...
#define TPM_DA_STATE_INACTIVE ...
#define TPM_DA_STATE_ACTIVE ...
#define TPM_DA_ACTION_TIMEOUT ...
#define TPM_DA_ACTION_DISABLE ...
#define TPM_DA_ACTION_DEACTIVATE ...
#define TPM_DA_ACTION_FAILURE_MODE ...
#define TPM_DAA_SIZE_r0 ...
#define TPM_DAA_SIZE_r1 ...
#define TPM_DAA_SIZE_r2 ...
#define TPM_DAA_SIZE_r3 ...
#define TPM_DAA_SIZE_r4 ...
#define TPM_DAA_SIZE_NT ...
#define TPM_DAA_SIZE_v0 ...
#define TPM_DAA_SIZE_v1 ...
#define TPM_DAA_SIZE_NE ...
#define TPM_DAA_SIZE_w ...
#define TPM_DAA_SIZE_issuerModulus ...
#define TPM_DAA_power0 ...
#define TPM_DAA_power1 ...
#define TPM_REDIR_GPIO ...
#define TPM_SYM_MODE_ECB ...
#define TPM_SYM_MODE_CBC ...
#define TPM_SYM_MODE_CFB ...
#define TPM_E_BASE ...
#define TPM_E_NON_FATAL ...
#define TPM_SUCCESS ...
#define TPM_E_AUTHFAIL ...
#define TPM_E_BADINDEX ...
#define TPM_E_BAD_PARAMETER ...
#define TPM_E_AUDITFAILURE ...
#define TPM_E_CLEAR_DISABLED ...
#define TPM_E_DEACTIVATED ...
#define TPM_E_DISABLED ...
#define TPM_E_DISABLED_CMD ...
#define TPM_E_FAIL ...
#define TPM_E_BAD_ORDINAL ...
#define TPM_E_INSTALL_DISABLED ...
#define TPM_E_INVALID_KEYHANDLE ...
#define TPM_E_KEYNOTFOUND ...
#define TPM_E_INAPPROPRIATE_ENC ...
#define TPM_E_MIGRATEFAIL ...
#define TPM_E_INVALID_PCR_INFO ...
#define TPM_E_NOSPACE ...
#define TPM_E_NOSRK ...
#define TPM_E_NOTSEALED_BLOB ...
#define TPM_E_OWNER_SET ...
#define TPM_E_RESOURCES ...
#define TPM_E_SHORTRANDOM ...
#define TPM_E_SIZE ...
#define TPM_E_WRONGPCRVAL ...
#define TPM_E_BAD_PARAM_SIZE ...
#define TPM_E_SHA_THREAD ...
#define TPM_E_SHA_ERROR ...
#define TPM_E_FAILEDSELFTEST ...
#define TPM_E_AUTH2FAIL ...
#define TPM_E_BADTAG ...
#define TPM_E_IOERROR ...
#define TPM_E_ENCRYPT_ERROR ...
#define TPM_E_DECRYPT_ERROR ...
#define TPM_E_INVALID_AUTHHANDLE ...
#define TPM_E_NO_ENDORSEMENT ...
#define TPM_E_INVALID_KEYUSAGE ...
#define TPM_E_WRONG_ENTITYTYPE ...
#define TPM_E_INVALID_POSTINIT ...
#define TPM_E_INAPPROPRIATE_SIG ...
#define TPM_E_BAD_KEY_PROPERTY ...
#define TPM_E_BAD_MIGRATION ...
#define TPM_E_BAD_SCHEME ...
#define TPM_E_BAD_DATASIZE ...
#define TPM_E_BAD_MODE ...
#define TPM_E_BAD_PRESENCE ...
#define TPM_E_BAD_VERSION ...
#define TPM_E_NO_WRAP_TRANSPORT ...
#define TPM_E_AUDITFAIL_UNSUCCESSFUL ...
#define TPM_E_AUDITFAIL_SUCCESSFUL ...
#define TPM_E_NOTRESETABLE ...
#define TPM_E_NOTLOCAL ...
#define TPM_E_BAD_TYPE ...
#define TPM_E_INVALID_RESOURCE ...
#define TPM_E_NOTFIPS ...
#define TPM_E_INVALID_FAMILY ...
#define TPM_E_NO_NV_PERMISSION ...
#define TPM_E_REQUIRES_SIGN ...
#define TPM_E_KEY_NOTSUPPORTED ...
#define TPM_E_AUTH_CONFLICT ...
#define TPM_E_AREA_LOCKED ...
#define TPM_E_BAD_LOCALITY ...
#define TPM_E_READ_ONLY ...
#define TPM_E_PER_NOWRITE ...
#define TPM_E_FAMILYCOUNT ...
#define TPM_E_WRITE_LOCKED ...
#define TPM_E_BAD_ATTRIBUTES ...
#define TPM_E_INVALID_STRUCTURE ...
#define TPM_E_KEY_OWNER_CONTROL ...
#define TPM_E_BAD_COUNTER ...
#define TPM_E_NOT_FULLWRITE ...
#define TPM_E_CONTEXT_GAP ...
#define TPM_E_MAXNVWRITES ...
#define TPM_E_NOOPERATOR ...
#define TPM_E_RESOURCEMISSING ...
#define TPM_E_DELEGATE_LOCK ...
#define TPM_E_DELEGATE_FAMILY ...
#define TPM_E_DELEGATE_ADMIN ...
#define TPM_E_TRANSPORT_NOTEXCLUSIVE ...
#define TPM_E_OWNER_CONTROL ...
#define TPM_E_DAA_RESOURCES ...
#define TPM_E_DAA_INPUT_DATA0 ...
#define TPM_E_DAA_INPUT_DATA1 ...
#define TPM_E_DAA_ISSUER_SETTINGS ...
#define TPM_E_DAA_TPM_SETTINGS ...
#define TPM_E_DAA_STAGE ...
#define TPM_E_DAA_ISSUER_VALIDITY ...
#define TPM_E_DAA_WRONG_W ...
#define TPM_E_BAD_HANDLE ...
#define TPM_E_BAD_DELEGATE ...
#define TPM_E_BADCONTEXT ...
#define TPM_E_TOOMANYCONTEXTS ...
#define TPM_E_MA_TICKET_SIGNATURE ...
#define TPM_E_MA_DESTINATION ...
#define TPM_E_MA_SOURCE ...
#define TPM_E_MA_AUTHORITY ...
#define TPM_E_PERMANENTEK ...
#define TPM_E_BAD_SIGNATURE ...
#define TPM_E_NOCONTEXTSPACE ...
#define TPM_E_RETRY ...
#define TPM_E_NEEDS_SELFTEST ...
#define TPM_E_DOING_SELFTEST ...
#define TPM_E_DEFEND_LOCK_RUNNING ...
