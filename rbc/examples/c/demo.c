/*
 * demo.c — minimal RBC C client.
 *
 * Build (after `cargo build -p rbc`):
 *   cc -I rbc/include rbc/examples/c/demo.c \
 *      -L target/debug -lrbc -lpthread -ldl -lm \
 *      -o /tmp/rbc_demo
 *
 * Run:
 *   LD_LIBRARY_PATH=target/debug /tmp/rbc_demo rbc/conf/rbc.yaml some/resource/uri
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rbc.h"

static void die(const char *where, RbcErrorCode code) {
    const char *msg = RbcLastErrorMessage();
    fprintf(stderr, "%s failed (code=%d): %s\n",
            where, (int)code, msg ? msg : "(no message)");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <config.yaml> <resource_uri>\n", argv[0]);
        return 2;
    }

    const char *config_path  = argv[1];
    const char *resource_uri = argv[2];

    RbcClient *client = NULL;
    RbcErrorCode rc = RbcClientNewFromFile(config_path, &client);
    if (rc != RBC_ERROR_CODE_OK) die("RbcClientNewFromFile", rc);

    char *nonce = NULL;
    rc = RbcGetAuthChallenge(client, &nonce);
    if (rc != RBC_ERROR_CODE_OK) die("RbcGetAuthChallenge", rc);
    printf("nonce: %s\n", nonce);

    RbcSession *session = NULL;
    rc = RbcSessionNew(client, NULL, &session);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionBegin", rc);

    // get evidence
    char *evidence = NULL;
    rc = RbcSessionCollectEvidence(session, nonce, &evidence);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionCollectEvidence", rc);

    char *token = NULL;
    rc = RbcSessionAttest(session, evidence, &token);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionAttest", rc);
    printf("token: %.40s...\n", token);

    RbcResource *res = NULL;
    rc = RbcSessionGetResourceByToken(session, resource_uri, token, &res);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionGetResourceByToken", rc);

    size_t n = 0;
    const uint8_t *content = RbcResourceGetContent(res, &n);
    const char *ctype = RbcResourceGetContentType(res);
    printf("resource uri: %s\n", RbcResourceGetUri(res));
    printf("content-type: %s\n", ctype ? ctype : "(none)");
    printf("content (%zu bytes): %.*s\n", n, (int)n, (const char *)content);

    /* If the content is a JWE envelope, decrypt it here:
     *   uint8_t *pt = NULL; size_t pt_len = 0;
     *   rc = RbcSessionDecryptContent(session, (const char *)content, NULL,
     *                                 &pt, &pt_len);
     *   ...
     *   RbcBufferFree(pt, pt_len);
     */

    RbcResourceFree(res);
    RbcStringFree(token);
    RbcStringFree(evidence);
    RbcSessionFree(session);
    RbcStringFree(nonce);
    RbcClientFree(client);
    return 0;
}
