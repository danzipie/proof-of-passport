pragma circom 2.1.5;

include "@zk-email/circuits/helpers/rsa.circom";
include "@zk-email/circuits/helpers/extract.circom";
include "@zk-email/circuits/helpers/sha.circom";
include "./Sha256BytesStatic.circom";
include "./sha1-circom/circuits/sha1.circom";

template PassportVerifier(n, k, max_datahashes_bytes, digest_type) {
    signal input mrz[93]; // formatted mrz (5 + 88) chars
    signal input dataHashes[max_datahashes_bytes];
    signal input datahashes_padded_length;
    signal input eContentBytes[104];

    signal input pubkey[k];
    signal input signature[k];

    var digest_size;
    if (digest_type == 0) { // sha256
        digest_size = 256;
    } else { // sha1
        digest_size = 160;
    }

    var digest_size_bytes = digest_size / 8;

    signal mrzSha[digest_size];
    component hash_bytes[digest_size_bytes];
    // compute hash of formatted mrz
    if (digest_size == 256) {
        mrzSha <== Sha256BytesStatic(93)(mrz);
    } else if (digest_size == 160) {
        mrzSha <== Sha1(93)(mrz);
    }

    // get output of hash into bytes to check against dataHashes
    for (var i = 0; i < digest_size_bytes; i++) {
        hash_bytes[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            hash_bytes[i].in[7 - j] <== mrzSha[i * 8 + j];
        }
    }

    // check that it is in the right position in dataHashes
    for(var i = 0; i < digest_size_bytes; i++) {
        dataHashes[31 + i] === hash_bytes[i].out;
    }

    // hash dataHashes dynamically
    signal dataHashesSha[digest_size];
    if (digest_size == 256) {
        dataHashesSha <== Sha256Bytes(max_datahashes_bytes)(dataHashes, datahashes_padded_length);
    } else if (digest_size == 160) {
        dataHashesSha <== Sha1(max_datahashes_bytes)(dataHashes);
    }

    // get output of dataHashes digest into bytes to check against eContent
    component dataHashes_digest_bytes[digest_size_bytes];
    for (var i = 0; i < digest_size_bytes; i++) {
        dataHashes_digest_bytes[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            dataHashes_digest_bytes[i].in[7 - j] <== dataHashesSha[i * 8 + j];
        }
    }

    // check that it is in the right position in eContent
    for(var i = 0; i < digest_size_bytes; i++) {
        eContentBytes[72 + i] === dataHashes_digest_bytes[i].out;
    }

    // hash eContentBytes
    signal eContentSha[digest_size];
    if (digest_size == 256) {
        eContentSha <== Sha256BytesStatic(104)(eContentBytes);
    } else if (digest_size == 160) {
        eContentSha <== Sha1(104)(eContentBytes);
    }

    // get output of eContentBytes digest into k chunks of n bits each
    var msg_len = (digest_size + n) \ n;

    component eContentHash[msg_len];
    for (var i = 0; i < msg_len; i++) {
        eContentHash[i] = Bits2Num(n);
    }
    for (var i = 0; i < digest_size; i++) {
        eContentHash[i \ n].in[i % n] <== eContentSha[digest_size - 1 - i];
    }
    for (var i = digest_size; i < n * msg_len; i++) {
        eContentHash[i \ n].in[i % n] <== 0;
    }
    
    // verify eContentHash signature
    component rsa = RSAVerify65537(64, 32);

    for (var i = 0; i < msg_len; i++) {
        rsa.base_message[i] <== eContentHash[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.base_message[i] <== 0;
    }
    rsa.modulus <== pubkey;
    rsa.signature <== signature;
}