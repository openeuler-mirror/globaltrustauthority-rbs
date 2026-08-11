#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rbc.h"

static void fail(const char *operation, RbcErrorCode code) {
    const char *message = RbcLastErrorMessage();
    fprintf(stderr, "%s failed (%d): %s\n", operation, (int)code,
            message == NULL ? "no error message" : message);
    exit(1);
}

static int token_segment_count(const char *token) {
    int dots = 0;
    for (const char *cursor = token; *cursor != '\0'; ++cursor) {
        if (*cursor == '.') dots++;
    }
    return dots + 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s CONFIG RESOURCE_URI EXPECTED_JSON\n", argv[0]);
        return 2;
    }

    RbcClient *client = NULL;
    RbcSession *session = NULL;
    RbcResource *resource = NULL;
    char *nonce = NULL;
    char *evidence = NULL;
    char *token = NULL;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    RbcErrorCode code;

    code = RbcClientNewFromFile(argv[1], &client);
    if (code != RBC_ERROR_CODE_OK) fail("RbcClientNewFromFile", code);
    code = RbcGetAuthChallenge(client, &nonce);
    if (code != RBC_ERROR_CODE_OK) fail("RbcGetAuthChallenge", code);
    code = RbcSessionNew(client, NULL, &session);
    if (code != RBC_ERROR_CODE_OK) fail("RbcSessionNew", code);
    code = RbcSessionCollectEvidence(session, nonce, &evidence);
    if (code != RBC_ERROR_CODE_OK) fail("RbcSessionCollectEvidence", code);
    code = RbcSessionAttest(session, evidence, &token);
    if (code != RBC_ERROR_CODE_OK) fail("RbcSessionAttest", code);
    code = RbcSessionGetResourceByToken(session, argv[2], token, &resource);
    if (code != RBC_ERROR_CODE_OK) fail("RbcSessionGetResourceByToken", code);

    size_t encrypted_len = 0;
    const uint8_t *encrypted = RbcResourceGetContent(resource, &encrypted_len);
    char *jwe = malloc(encrypted_len + 1);
    if (jwe == NULL) return 3;
    memcpy(jwe, encrypted, encrypted_len);
    jwe[encrypted_len] = '\0';
    code = RbcSessionDecryptContent(session, jwe, NULL, NULL, 0, &plaintext, &plaintext_len);
    free(jwe);
    if (code != RBC_ERROR_CODE_OK) fail("RbcSessionDecryptContent", code);

    size_t expected_len = strlen(argv[3]);
    int matches = plaintext_len == expected_len && memcmp(plaintext, argv[3], expected_len) == 0;
    int token_segments = token_segment_count(token);
    int valid_flow = nonce[0] != '\0' && token_segments == 3 && matches;
    printf("{\"nonce_present\":%s,\"token_segments\":%d,\"plaintext_matches\":%s}\n",
           nonce[0] == '\0' ? "false" : "true", token_segments, matches ? "true" : "false");

    RbcBufferFree(plaintext, plaintext_len);
    RbcResourceFree(resource);
    RbcStringFree(token);
    RbcStringFree(evidence);
    RbcSessionFree(session);
    RbcStringFree(nonce);
    RbcClientFree(client);
    return valid_flow ? 0 : 4;
}
