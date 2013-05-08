from pytss import TspiContext
from tspi_defines import *
import tspi_exceptions
import uuid
import M2Crypto
from M2Crypto import m2
import pyasn1
import hashlib
import os
import struct
import base64

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')


def integer_ceil(a, b):
    """Return the ceil integer of a div b."""
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta


def i2osp(x, x_len):
    """
    Converts the integer x to its big-endian representation of length
    x_len.
    """
    if x > 256**x_len:
        raise exceptions.IntegerTooLarge
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = h.decode('hex')
    return '\x00' * int(x_len-len(x)) + x


def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    """
    Mask Generation Function v1 from the PKCS#1 v2.0 standard.

    :param mgs_seed: the seed, a byte string
    :param mask_len: the length of the mask to generate
    :param hash_class: the digest algorithm to use, default is SHA1

    :returns:: a pseudo-random mask, as a byte string
    """
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = ''
    for i in xrange(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return bytearray(T[:mask_len])


def tpm_oaep(plaintext, keylen):
    """Pad plaintext with the TPM-specific varient of OAEP

    :param plaintext: The data that requires padding
    :param keylen: The length of the encryption key
    :returns: a padded plaintext
    """
    m = hashlib.sha1()
    m.update('TCPA')

    seed = os.urandom(20)
    seedstart = 1
    seedend = seedstart + m.digest_size

    output = bytearray(keylen)
    output[0] = 0
    output[seedstart:seedend] = seed

    shastart = 21
    shaend = 21 + m.digest_size
    output[shastart:shaend] = m.digest()

    output[-(len(plaintext)+1)] = 1
    offset = keylen - len(plaintext)
    output[offset:keylen] = plaintext

    dbmask = mgf1(seed, keylen - m.digest_size - 1)
    for i in range(shastart, keylen):
        output[i] ^= dbmask[i - shastart]

    seedmask = mgf1(output[seedend:keylen], m.digest_size)
    for i in range(seedstart, seedend):
        output[i] ^= seedmask[i-1]

    return output


def get_ekcert(context):
    """Retrieve the Endoresement Key's certificate from the TPM.

    :param context: The TSS context to use
    :returns: a bytearray containing the x509 certificate
    """
    # fixme
    nvIndex = TSS_NV_DEFINED | TPM_NV_INDEX_EKCert

    nv = context.create_nv(0)
    nv.set_index(nvIndex)

    # Try reading without authentication, and then fall back to using the
    # well known secret
    try:
        blob = nv.read_value(0, 5)
    except tspi_exceptions.TPM_E_AUTH_CONFLICT:
        policy = context.create_policy(TSS_POLICY_USAGE)
        policy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)
        policy.assign(nv)
        blob = nv.read_value(0, 5)

    # Verify that the certificate is well formed
    tag = blob[0] << 8 | blob[1]
    if tag != 0x1001:
            print "Invalid tag %x %x\n" % (blob[0], blob[1])
            return None

    certtype = blob[2]
    if certtype != 0:
            print "Not a full certificate\n"
            return None

    ekbuflen = blob[3] << 8 | blob[4]
    offset = 5

    blob = nv.read_value(offset, 2)
    if len(blob) < 2:
        print "Invalid length"
        return None

    tag = blob[0] << 8 | blob[1]
    if tag == 0x1002:
        offset += 2
        ekbuflen -= 2
    elif blob[0] != 0x30:
        print "Invalid header %x %x" % (blob[0], blob[1])
        return None
    
    ekbuf = bytearray()
    ekoffset = 0

    while ekoffset < ekbuflen:
        length = ekbuflen-ekoffset
        if length > 128:
            length = 128
        blob = nv.read_value(offset, length)
        ekbuf += blob
        offset += len(blob)
        ekoffset += len(blob)

    return ekbuf


def create_aik(context):
    """Ask the TPM to create an Authorisation Identity Key

    :param context: The TSS context to use
    :returns: a tuple containing the RSA public key and a TSS key blob
    """

    n = bytearray([0xff] * (2048/8))

    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

    keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    tpm = context.get_tpm_object()
    tpmpolicy = context.create_policy(TSS_POLICY_USAGE)
    tpmpolicy.assign(tpm)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    pcakey = context.create_rsa_key(flags=TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048)
    pcakey.set_attribute_data(TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, n)

    aik = context.create_rsa_key(flags=TSS_KEY_TYPE_IDENTITY|TSS_KEY_SIZE_2048)

    data = tpm.collate_identity_request(srk, pcakey, aik)

    pubkey = aik.get_attribute_data(TSS_TSPATTRIB_KEY_BLOB,
                                    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY)
    blob = aik.get_attribute_data(TSS_TSPATTRIB_KEY_BLOB,
                                  TSS_TSPATTRIB_KEYBLOB_BLOB)

    return (pubkey, blob)


def verify_aik(context, pubkey, ekcert):
    """Verify that the provided EK certificate is signed by a trusted root

    :param context: The TSS context to use
    :param pubkey: The public half of the AIK
    :param ekcert: The Endorsement Key certificate
    :returns: True if the certificate can be verified, false otherwise
    """
    # FIXME implement
    return True

def generate_challenge(context, ekcert, aikpub, secret):
    """ Generate a challenge to verify that the AIK is under the control of
    the TPM we're talking to.

    :param context: The TSS context to use
    :param ekcert: The Endorsement Key certificate
    :param aikpub: The public Attestation Identity Key
    :param secret: The secret to challenge the TPM with
    :returns: a tuple containing the asymmetric and symmetric components of
    the challenge
    """

    aeskey = bytearray(os.urandom(16))
    iv = bytearray(os.urandom(16))

    # Replace rsaesOaep OID with rsaEncryption
    ekcert = ekcert.replace('\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07',
                            '\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01')

    x509 = M2Crypto.X509.load_cert_string(ekcert, M2Crypto.X509.FORMAT_DER)
    pubkey = x509.get_pubkey()
    rsakey = pubkey.get_rsa()

    # TPM_ALG_AES, TPM_ES_SYM_CBC_PKCS5PAD, key length
    asymplain = bytearray([0x00, 0x00, 0x00, 0x06, 0x00, 0xff, 0x00, 0x10])
    asymplain += aeskey

    m = hashlib.sha1()
    m.update(aikpub)
    asymplain += m.digest()

    # Pad with the TCG varient of OAEP
    asymplain = tpm_oaep(asymplain, pubkey.size())

    # Generate the EKpub-encrypted asymmetric buffer containing the aes key
    asymenc = bytearray(rsakey.public_encrypt(asymplain,
                                              M2Crypto.RSA.no_padding))

    # And symmetrically encrypt the secret with AES
    cipher = M2Crypto.EVP.Cipher('aes_128_cbc', aeskey, iv, 1)
    cipher.update(secret)
    symenc = cipher.final()

    symheader = struct.pack('!llhhllll', len(symenc) + len(iv),
                            TPM_ALG_AES, TPM_ES_SYM_CBC_PKCS5PAD,
                            TPM_SS_NONE, 12, 128, len(iv), 0)

    symenc = symheader + iv + symenc

    return (asymenc, symenc)


def aik_challenge_response(context, aikblob, asymchallenge, symchallenge):
    """Ask the TPM to respond to a challenge

    :param context: The TSS context to use
    :param aikblob: The Attestation Identity Key blob
    :param asymchallenge: The asymmetrically encrypted challenge
    :param symchallenge: The symmertrically encrypted challenge    
    :returns: The decrypted challenge
    """

    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    tpm = context.get_tpm_object()
    tpmpolicy = context.create_policy(TSS_POLICY_USAGE)
    tpmpolicy.assign(tpm)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    aik = context.load_key_by_blob(srk, aikblob)

    try:
        return tpm.activate_identity(aik, asymchallenge, symchallenge)
    except tspi_exceptions.TPM_E_DECRYPT_ERROR:
        return None

def quote_verify(data, validation, aik, pcrvalues):
    """Verify that a generated quote came from a trusted TPM and matches the
    previously obtained PCR values

    :param data: The TPM_QUOTE_INFO structure provided by the TPM
    :param validation: The validation information provided by the TPM
    :param aik: The object representing the Attestation Identity Key
    :param pcrvalues: A dictionary containing the PCRs read from the TPM
    :returns: True if the quote can be verified, False otherwise
    """
    select = 0
    maxpcr = 0

    # Verify that the validation blob was generated by a trusted TPM
    pubkey = aik.get_attribute_data(TSS_TSPATTRIB_RSAKEY_INFO,
                                    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS)

    n = m2.bin_to_bn(pubkey)
    n = m2.bn_to_mpi(n)
    e = m2.hex_to_bn("010001")
    e = m2.bn_to_mpi(e)
    rsa = M2Crypto.RSA.new_pub_key((e, n))

    m = hashlib.sha1()
    m.update(data)
    md = m.digest()

    try:
        ret = rsa.verify(md, str(validation), algo='sha1')
    except M2Crypto.RSA.RSAError:
        return False

    # And then verify that the validation blob corresponds to the PCR
    # values we have
    values = bytearray()

    for pcr in sorted(pcrvalues):
        values += pcrvalues[pcr]
        select |= (1 << pcr)
        maxpcr = pcr

    if maxpcr < 16:
        header = struct.pack('!H', 2)
        header += struct.pack('@H', select)
        header += struct.pack('!I', len(values))
    else:
        header = struct.pack('!H', 4)
        header += struct.pack('@I', select)
        header += struct.pack('!I', len(values))

    pcr_blob = header + values

    m = hashlib.sha1()
    m.update(pcr_blob)
    pcr_hash = m.digest()

    if pcr_hash == data[8:28]:
        return True
    else:
        return False
