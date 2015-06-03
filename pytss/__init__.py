from interface import tss_lib, ffi
import tspi_exceptions
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

        :param sectype: The type of the secret, any of the constants
            prefixed TSS_SECRET_MODE_ in tspi_defines
        :param secret: The secret data blob as either a string or
            array of integers in the range 0..255
        """
        tss_lib.Tspi_Policy_SetSecret(self.handle[0], sectype, len(secret),
                                      _c_byte_array(secret))

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
        tss_lib.Tspi_Hash_UpdateHashValue(self.get_handle(), len(data),
                                          _c_byte_array(data))

    def verify(self, key, signature):
        """
        Verify that the hash matches a given signature

        :param key: A TspiObject representing the key to use
        :param signature: The signature to compare against
        """
        tss_lib.Tspi_Hash_VerifySignature(self.get_handle(), key.get_handle(),
                                     len(signature), _c_byte_array(signature))

    def sign(self, key):
        """
        Sign this hash with the specified key and return a signature

        :param key: a TspiKey instance corresponding to a loaded key
        :return: a string of bytes containing the signature
        """
        csig_size = ffi.new("UINT32*")
        csig_data = ffi.new("BYTE**")
        tss_lib.Tspi_Hash_Sign(self.get_handle(), key.get_handle(), csig_size, csig_data)
        return ffi.buffer(csig_data[0], csig_size[0])


class TspiKey(TspiObject):
    def __init__(self, context, flags, handle=None):
        self.context = context
        super(TspiKey, self).__init__(context, 'TSS_HKEY *',
                                      tss_lib.TSS_OBJECT_TYPE_RSAKEY,
                                      flags, handle)

    def __del__(self):
        try:
            tss_lib.Tspi_Key_UnloadKey(self.get_handle())
        # The key may have been implicitly unloaded as part of a previous
        # operation
        except tspi_exceptions.TSS_E_INVALID_HANDLE:
            pass

    def set_modulus(self, n):
        """
        Set the key modulus

        :param n: The key modulus
        """
        self.set_attribute_data(tss_lib.TSS_TSPATTRIB_RSAKEY_INFO,
                                tss_lib.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, n)

    def get_keyblob(self):
        """
        Obtain a TSS blob corresponding to the key

        :returns: a bytearray containing the TSS key blob
        """
        return self.get_attribute_data(tss_lib.TSS_TSPATTRIB_KEY_BLOB,
                                       tss_lib.TSS_TSPATTRIB_KEYBLOB_BLOB)

    def get_pubkeyblob(self):
        """
        Obtain a TSS blob corresponding to the public portion of the key

        :returns: a bytearray containing the TSS key blob
        """
        return self.get_attribute_data(tss_lib.TSS_TSPATTRIB_KEY_BLOB,
                                       tss_lib.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY)

    def get_pubkey(self):
        """
        Obtain the public part of the key

        :returns: a bytearray containing the public portion of the key
        """
        return self.get_attribute_data(tss_lib.TSS_TSPATTRIB_RSAKEY_INFO,
                                       tss_lib.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS)


    def seal(self, data, pcrs=None):
        """
        Seal data to the local TPM using this key

        :param data: The data to seal
        :param pcrs: A list of PCRs to seal the data to

        :returns: a bytearray of the encrypted data
        """
        encdata = TspiObject(self.context, 'TSS_HENCDATA *',
                             tss_lib.TSS_OBJECT_TYPE_ENCDATA,
                             tss_lib.TSS_ENCDATA_SEAL)

        if pcrs is not None:
            pcrobj=TspiPCRs(self.context, tss_lib.TSS_PCRS_STRUCT_INFO)
            pcrobj.set_pcrs(pcrs)
            pcr_composite = pcrobj.get_handle()
        else:
            pcr_composite = 0

        cdata = ffi.new('BYTE[]', len(data))
        for i in range(len(data)):
            cdata[i] = data[i]

        tss_lib.Tspi_Data_Seal(encdata.get_handle(), self.get_handle(),
                               len(data), cdata, pcr_composite)
        blob = encdata.get_attribute_data(tss_lib.TSS_TSPATTRIB_ENCDATA_BLOB,
                                    tss_lib.TSS_TSPATTRIB_ENCDATABLOB_BLOB)
        return bytearray(blob)

    def unseal(self, data):
        """
        Unseal data from the local TPM using this key

        :param data: The data to unseal

        :returns: a bytearray of the unencrypted data
        """
        encdata = TspiObject(self.context, 'TSS_HENCDATA *',
                             tss_lib.TSS_OBJECT_TYPE_ENCDATA,
                             tss_lib.TSS_ENCDATA_SEAL)

        encdata.set_attribute_data(tss_lib.TSS_TSPATTRIB_ENCDATA_BLOB,
                                tss_lib.TSS_TSPATTRIB_ENCDATABLOB_BLOB, data)

        bloblen = ffi.new('UINT32 *')
        blob = ffi.new('BYTE **')

        tss_lib.Tspi_Data_Unseal(encdata.get_handle(), self.get_handle(),
                                 bloblen, blob)
        ret = bytearray(blob[0][0:bloblen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, blob[0])
        return ret


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

    def get_pub_endorsement_key(self):
        keyblob = ffi.new('TSS_HKEY *')
        modulus = ffi.new('UINT32 *')
        modlen = ffi.new('BYTE **')
        tss_lib.Tspi_TPM_GetPubEndorsementKey(self.get_handle(), 1, ffi.NULL,
                                              keyblob)
        key = TspiKey(self.context, None, handle=keyblob)
        return key

    def take_ownership(self, srk):
        """
        Take ownership of the TPM

        :param srk: The Storage Root Key to use
        """
        tss_lib.Tspi_TPM_TakeOwnership(self.get_handle(), srk.get_handle(), 0)

    def extend_pcr(self, pcr, data, event):
        """
        Extend a PCR

        :param pcr: The PCR to extend
        :param data: The data to be hashed by the TPM for extending the PCR
        :param event: A dict containing the event data

        :returns: A bytearray containing the new PCR value
        """
        cdata = ffi.new('BYTE []', len(data))
        bloblen = ffi.new('UINT32 *')
        blob = ffi.new('BYTE **')
        for i in range(len(data)):
            cdata[i] = data[i]

        tss_lib.Tspi_TPM_PcrExtend(self.get_handle(), pcr, len(data), cdata,
                                   ffi.NULL, bloblen, blob)
        ret = bytearray(blob[0][0:bloblen[0]])
        tss_lib.Tspi_Context_FreeMemory(self.context, blob[0])
        return ret

class TspiContext():
    def __init__(self):
        self.context = ffi.new('TSS_HCONTEXT *')
        tss_lib.Tspi_Context_Create(self.context)
        self.context = self.context[0]
        self.tpm = None

    def __del__(self):
        tss_lib.Tspi_Context_Close(self.context)

    def connect(self, host=None):
        """
        Connect a context to a TSS daemon

        :param host: The host to connect to, if not localhost
        """
        if host is not None:
            chost = ffi.new('uint16_t[]', len(host) + 1)
            for i in range(len(host)):
                chost[i] = bytearray(host)[i]
            chost[len(host)] = 0
            tss_lib.Tspi_Context_Connect(self.context, chost)
        else:
            tss_lib.Tspi_Context_Connect(self.context, ffi.NULL)
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

    def create_rsa_key(self, flags):
        """
        Create a Tspi key object associated with this context

        :param flags: Flags to pass
        """
        obj = TspiKey(self.context, flags)
        return obj

    def load_key_by_uuid(self, storagetype, uuid):
        """
        Load a key that's been registered in persistent storage

        :param storagetype: The key storage type
        :param uuid: The UUID associated with the key

        :returns: a TspiKey
        """
        tss_key = ffi.new('TSS_HKEY *')
        tss_uuid = uuid_to_tss_uuid(uuid)
        tss_lib.Tspi_Context_LoadKeyByUUID(self.context, storagetype, tss_uuid,
                                       tss_key)
        key = TspiKey(self.context, None, handle=tss_key)
        return key

    def load_key_by_blob(self, srk, blob):
        """
        Load a key from a TSS key blob

        :param srk: A TspiObject representing the Storage Root key
        :param blob: The TSS key blob

        :returns: A TspiKey
        """
        tss_key = ffi.new('TSS_HKEY *')
        cblob = ffi.new('BYTE[]', len(blob))
        for i in range(len(blob)):
            cblob[i] = blob[i]
        tss_lib.Tspi_Context_LoadKeyByBlob(self.context, srk.get_handle(),
                                       len(blob), cblob, tss_key)
        key = TspiKey(self.context, None, handle=tss_key)
        return key

    def get_tpm_object(self):
        """Returns the TspiTPM associated with this context"""        
        return self.tpm


def _c_byte_array(data):
    """
    Creates and returns a ffi BYTE[] type containing data.
    :param data: a string of bytes or array of integers in range 0x00..0xff
    :return: ffi cdata instance backed by a c BYTE[] structure containing
        the contents of data
    """
    cdata = ffi.new('BYTE []', len(data))
    if isinstance(data, basestring):
        data = bytearray(data)
    for i in range(len(data)):
        cdata[i] = data[i]
    return cdata
