from interface import tss_lib, ffi
import hashlib


def uuid_to_tss_uuid(uuid):
    """Converts a Python UUID into a TSS UUID"""
    tss_uuid = ffi.new('struct tdTSS_UUID *')[0]
    tss_uuid.ulTimeLow = uuid.time_low
    tss_uuid.usTimeMid = uuid.time_mid
    tss_uuid.usTimeHigh = uuid.time_hi_version
    tss_uuid.bClockSeqHigh = uuid.clock_seq_hi_variant
    tss_uuid.bClockSeqLow = uuid.clock_seq_low
    tss_uuid.rgbNode[0] = (uuid.node >> 40) & 0xff
    tss_uuid.rgbNode[1] = (uuid.node >> 32) & 0xff
    tss_uuid.rgbNode[2] = (uuid.node >> 24) & 0xff
    tss_uuid.rgbNode[3] = (uuid.node >> 16) & 0xff
    tss_uuid.rgbNode[4] = (uuid.node >> 8) & 0xff
    tss_uuid.rgbNode[5] = uuid.node & 0xff

    return tss_uuid


class TspiObject(object):
    def __init__(self, context, ctype, tss_type, flags, handle=None):
        """
        Init a TSPI object
        
        :param context: The TSS context to use
        :param ctype: The C type associated with this TSS object
        :param tss_type: The TSS type associated with this TSS object
        :param flags: The default attributes of the object
        :param handle: Use an existing handle, rather than creating a new
        object
        """
        self.context = context
        if handle is not None:
            self.handle = handle
        else:
            self.handle = ffi.new(ctype)
            tss_lib.Tspi_Context_CreateObject(context, tss_type, flags,
                                          self.handle)

    def get_handle(self):
        """Return the TSS handle for the object"""        
        return self.handle[0]

    def set_attribute_uint32(self, attrib, sub, val):
        """
        Set a 32 bit attribute associated with a given object
        
        :param attrib: The attribute to modify
        :param sub: The subattribute to modify
        :param val: The value to assign
        """
        tss_lib.Tspi_SetAttribUint32(self.get_handle(), attrib, sub, val)

    def set_attribute_data(self, attrib, sub, data):
        """
        Set an arbitrary datatype attribute associated with the object

        :param attrib: The attribute to modify
        :param sub: The subattribute to modify
        :param val: The data to assign
        """
        cdata = ffi.new('BYTE[]', len(data))
        for i in range(len(data)):
            cdata[i] = data[i]
        tss_lib.Tspi_SetAttribData(self.get_handle(), attrib, sub, len(data), cdata)

    def get_attribute_data(self, attrib, sub):
        """
        Get an arbitrary datatype associated with the object

        :param attrib: The attribute to modify
        :param sub: The subattribute to modify

        :returns: a bytearray containing the data
        """
        bloblen = ffi.new('UINT32 *')
        blob = ffi.new('BYTE **')
        tss_lib.Tspi_GetAttribData(self.handle[0], attrib, sub, bloblen, blob)
        ret = bytearray(blob[0][0:bloblen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, blob[0])
        return ret

    def get_policy_object(self, poltype):
        """
        Get a policy object assigned to the object

        :param poltype: The policy object type

        :returns: A TspiPolicy
        """
        policy = ffi.new('TSS_HPOLICY *')
        tss_lib.Tspi_GetPolicyObject(self.get_handle(), poltype, policy)
        policy_obj = TspiPolicy(self.context, None, handle=policy)
        return policy_obj


class TspiNV(TspiObject):
    def __init__(self, context, flags):
        super(TspiNV, self).__init__(context, 'TSS_HNVSTORE *',
                                     tss_lib.TSS_OBJECT_TYPE_NV, flags)

    def read_value(self, offset, length):
        """
        Read a value from TPM NVRAM

        :param offset: The offset in NVRAM to start reading
        :param length: The number of bytes of NVRAM to read
        :returns: A bytearray containing the requested data
        """
        lenval = ffi.new('UINT32 *')
        data = ffi.new('BYTE **')
        lenval[0] = length
        tss_lib.Tspi_NV_ReadValue(self.handle[0], offset, lenval, data)
        ret = bytearray(data[0][0:lenval[0]])
        return ret

    def set_index(self, index):
        """
        Select the requested NVRAM storage area index

        :param index: The storage area index to select
        """
        tss_lib.Tspi_SetAttribUint32(self.handle[0], tss_lib.TSS_TSPATTRIB_NV_INDEX,
                                 0, index)


class TspiPolicy(TspiObject):
    def __init__(self, context, flags, handle=None):
        super(TspiPolicy, self).__init__(context, 'TSS_HPOLICY *',
                                         tss_lib.TSS_OBJECT_TYPE_POLICY, flags,
                                         handle)

    def set_secret(self, sectype, secret):
        """
        Set the authorisation data of a policy object

        :param sectype: The type of the secret
        :param secret: The secret data blob
        """
        csecret = ffi.new('BYTE[]', len(secret))
        for i in range(len(secret)):
            csecret[i] = secret[i]
        tss_lib.Tspi_Policy_SetSecret(self.handle[0], sectype, len(secret), csecret)

    def assign(self, target):
        """
        Assign a policy to an object

        :param target: The object to which the policy will be assigned
        """
        tss_lib.Tspi_Policy_AssignToObject(self.handle[0], target.get_handle())


class TspiPCRs(TspiObject):
    def __init__(self, context, flags):
        self.pcrs = {}
        super(TspiPCRs, self).__init__(context, 'TSS_HPCRS *',
                                       tss_lib.TSS_OBJECT_TYPE_PCRS, flags)

    def set_pcrs(self, pcrs):
        """
        Set the PCRs referred to by this object

        :param pcrs: A list of integer PCRs
        """
        for pcr in pcrs:
            tss_lib.Tspi_PcrComposite_SelectPcrIndex(self.handle[0], pcr)
            self.pcrs[pcr] = ""

    def get_pcrs(self):
        """
        Get the digest value of the PCRs referred to by this object

        :returns: a dictionary of PCR/value pairs
        """
        for pcr in self.pcrs:
            buf = ffi.new('BYTE **')
            buflen = ffi.new('UINT32 *')
            tss_lib.Tspi_PcrComposite_GetPcrValue(self.handle[0], pcr, buflen, buf)
            self.pcrs[pcr] = bytearray(buf[0][0:buflen[0]])
            tss_lib.Tspi_Context_FreeMemory(self.context, buf[0])
        return self.pcrs


class TspiHash(TspiObject):
    def __init__(self, context, flags):
        super(TspiHash, self).__init__(context, 'TSS_HHASH *',
                                       tss_lib.TSS_OBJECT_TYPE_HASH, flags)

    def update(self, data):
        """
        Update the hash object with new data

        :param data: The data to hash
        """
        cdata = ffi.new('BYTE []', len(data))
        for i in range(len(data)):
            cdata[i] = data[i]
        tss_lib.TspiHash_UpdateHashValue(self.get_handle(), len(data), cdata)

    def verify(self, key, signature):
        """
        Verify that the hash matches a given signature

        :param key: A TspiObject representing the key to use
        :param signature: The signature to compare against
        """
        cquote = ffi.new('BYTE []', len(quote))
        for i in range(len(quote)):
            cquote[i] = quote[i]
        tss_lib.TspiHash_VerifySignature(self.get_handle(), key.get_handle(),
                                     len(quote), cquote)


class TspiTPM(TspiObject):
    def __init__(self, context):
        tpm = ffi.new('TSS_HTPM *')
        tss_lib.Tspi_Context_GetTpmObject(context, tpm)
        self.handle = tpm
        self.context = context

    def collate_identity_request(self, srk, pubkey, aik):
        """
        Generate everything required to authenticate the TPM to a third party

        :param srk: The storage root key to use
        :param pubkey: The key to use for signing the output key
        :param aik: The key to use as the identity key

        :returns: A bytearray containing a certificate request
        """
        bloblen = ffi.new('UINT32 *')
        blob = ffi.new('BYTE **')
        tss_lib.Tspi_TPM_CollateIdentityRequest(self.get_handle(), 
                                            srk.get_handle(),
                                            pubkey.get_handle(), 0, "",
                                            aik.get_handle(), tss_lib.TSS_ALG_AES,
                                            bloblen, blob)
        ret = bytearray(blob[0][0:bloblen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, blob[0])
        return ret

    def get_capability(self, cap, sub):
        """
        Get information on the capabilities of the TPM

        :param cap: The capability to query
        :param sub: The subcapability to query

        :returns: A bytearray containing the capability data
        """
        resp = ffi.new('BYTE **')
        resplen = ffi.new('UINT32 *')
        csub = ffi.new('BYTE []', len(sub))
        for i in range(len(sub)):
            csub[i] = sub[i]
        tss_lib.Tspi_TPM_Getcapability(self.handle[0], cap, len(sub), csub,
                                   resplen, resp)
        ret = bytearray(resp[0][0:resplen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, resp[0])
        return ret

    def get_quote(self, aik, pcrs, challenge):
        """
        retrieve a signed set of PCR values

        :param aik: A TspiObject representing the Attestation Identity Key
        :param pcrs: A TspiPCRs representing the PCRs to be quoted
        :param challenge: The challenge to use

        :returns: A tuple containing the quote data and the validation block
        """
        valid = ffi.new('TSS_VALIDATION *')
        chalmd = ffi.new('BYTE[]', 20)

        if challenge:
            m = hashlib.sha1()
            m.update(challenge)
            sha1 = bytearray(m.digest())
            for i in range(len(sha1)):
                chalmd[i] = sha1[i]

        valid[0].ulExternalDataLength = ffi.sizeof(chalmd)
        valid[0].rgbExternalData = chalmd

        tss_lib.Tspi_TPM_Quote(self.handle[0], aik.get_handle(), pcrs.get_handle(),
                           valid)

        data = bytearray(valid[0].rgbData[0:valid[0].ulDataLength])
        validation = bytearray(valid[0].rgbValidationData
                               [0:valid[0].ulValidationDataLength])
        tss_lib.Tspi_Context_FreeMemory(self.context, valid[0].rgbData)
        tss_lib.Tspi_Context_FreeMemory(self.context, valid[0].rgbValidationData)
        return (data, validation)

    def activate_identity(self, aik, asymblob, symblob):
        """
        Decrypt the challenge provided by the attestation host

        :param aik: A TspiObject representing the Attestation Identity Key
        :param asymblob: The asymmetrically encrypted challenge data
        :param symblob: The symmetrically encrypted challenge data

        :returns: A bytearray containing the decrypted challenge
        """
        casymblob = ffi.new('BYTE[]', len(asymblob))
        for i in range(len(asymblob)):
            casymblob[i] = asymblob[i]
        csymblob = ffi.new('BYTE[]', len(symblob))
        for i in range(len(symblob)):
            csymblob[i] = symblob[i]
        credlen = ffi.new('UINT32 *')
        cred = ffi.new('BYTE **')
        tss_lib.Tspi_TPM_ActivateIdentity(self.handle[0], aik.get_handle(),
                                      len(asymblob), casymblob,
                                      len(symblob), csymblob, credlen, cred)
        ret = bytearray(cred[0][0:credlen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, cred[0])
        return ret


class TspiContext():
    def __init__(self):
        self.context = ffi.new('TSS_HCONTEXT *')
        tss_lib.Tspi_Context_Create(self.context)
        self.context = self.context[0]
        self.tpm = None

    def connect(self, host=ffi.NULL):
        """
        Connect a context to a TSS daemon

        :param host: The host to connect to, if not localhost
        """
        if self.tpm is not None:
            print "Already connected"

        tss_lib.Tspi_Context_Connect(self.context, host)
        self.tpm = TspiTPM(self.context)

    def create_nv(self, flags):
        """
        Create a TspiNV object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiNV(self.context, flags)
        return obj

    def create_policy(self, flags):
        """
        Create a TspiPolicy object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiPolicy(self.context, flags)
        return obj

    def create_pcrs(self, flags):
        """
        Create a TspiPCRs object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiPCRs(self.context, flags)
        return obj

    def create_hash(self, flags):
        """
        Create a TspiHash object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiHash(self.context, flags)
        return obj

    def create_rsa_key(self, flags=0):
        """
        Create a Tspi key object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiObject(self.context, 'TSS_HKEY *',
                         tss_lib.TSS_OBJECT_TYPE_RSAKEY, flags)
        return obj

    def load_key_by_uuid(self, storagetype, uuid):
        """
        Load a key that's been registered in persistent storage

        :param storagetype: The key storage type
        :param uuid: The UUID associated with the key

        :returns: a TspiObject representing the key
        """
        tss_key = ffi.new('TSS_HKEY *')
        tss_uuid = uuid_to_tss_uuid(uuid)
        tss_lib.Tspi_Context_LoadKeyByUUID(self.context, storagetype, tss_uuid,
                                       tss_key)
        key = TspiObject(self.context, None, None, None, handle=tss_key)
        return key

    def load_key_by_blob(self, srk, blob):
        """
        Load a key from a TSS key blob

        :param srk: A TspiObject representing the Storage Root key
        :param blob: The TSS key blob

        :returns: A TspiObject representing the key
        """
        tss_key = ffi.new('TSS_HKEY *')
        cblob = ffi.new('BYTE[]', len(blob))
        for i in range(len(blob)):
            cblob[i] = blob[i]
        tss_lib.Tspi_Context_LoadKeyByBlob(self.context, srk.get_handle(),
                                       len(blob), cblob, tss_key)
        key = TspiObject(self.context, None, None, None, handle=tss_key)
        return key

    def get_tpm_object(self):
        """Returns the TspiTPM associated with this context"""        
        return self.tpm
