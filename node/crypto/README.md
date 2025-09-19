# crypto package

This package exists as a housing for tests that need external dependencies to
verify behaviors of types/tries, types/crypto, and types/schema. It is not
expected to hold any cryptography related implementations, those belong outside
of the node package. We leave the housing for these tests inside the node
package to make CI easier as the scripts and tooling are already built out to
run tests on node during the build process. At some point in the future, this
package will likely be migrated to an external tests package. If this is
performed, as a note to future developers who may take up this task – ensure
that these tests are still run as part of the build.