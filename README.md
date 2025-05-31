# WhatsApp AKD monitor

This project reads the audits published on the WhatsApp Key Transparency log
and counts the new nodes appended at each epoch (30 seconds).

## SEEMlees and the append-only tree

The key transparency protocol behind WhatsApp is based on [SEEMless: Secure End-to-End Encrypted Messaging with less trust](https://eprint.iacr.org/2018/607).

The protocol is meant to be Zero Knowledge. However, it's not fully ZK. The proof published for the auditors has one hash for each node in the append-only tree, so amount of the inserted nodes is leaked.

The data structure behind this protocol is a compressed Merkle tree. In the protocol, the server can only add new nodes to the tree. The auditor's role is to check that these nodes are inserted correctly in the tree.

Based on the specification in the paper, and assuming how WhatsApp works, we have the following assumptions:

    - Each node stores a user's public key
    - If a user changes its public key, a new node will be added for that public key
    - Existing nodes never change value
    - Every time a user installs whatsapp, the server generates a new public key for the user
    - A user might have multiple public keys


## Key transparency API

To read the published proofs, we use the library offered by facebook: https://github.com/facebook/akd.

Cloudflare also offers an auditor tool, called plexi: https://github.com/cloudflare/plexi. But it's too high level, and its purpose is mainly to verify the consistency of the proof chain.

Cloudflare KT API: https://developers.cloudflare.com/key-transparency/
