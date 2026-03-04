#!/bin/sh
# Marrow test runner - called by mk test
failed=0
for t in "$@"; do
    printf '%-44s ' "$t"
    if "$t" > /tmp/marrow_test_out 2>&1; then
        echo PASS
    else
        echo FAIL
        cat /tmp/marrow_test_out
        failed=1
    fi
done
exit $failed
