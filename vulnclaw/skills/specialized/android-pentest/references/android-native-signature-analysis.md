# Android Native Signature Analysis

Use this file when Android sign or crypto logic crosses from Java into JNI or `.so`.
Only enter this branch after runtime packet checks, Java triage, or hooks show that native analysis is actually needed.

## Owns

- Java-to-native boundary proof
- SO identification
- JNI style classification
- native sign-input and sign-output assessment
- decision on whether deeper native reversing is justified

## First Pass

Prove:

- which Java method declares `native`
- which `System.loadLibrary` or `System.load` call loads the target library
- whether JNI is static export or dynamic registration
- which parameters cross the boundary
- whether the return value is the final sign or an intermediate token

## Do Not Escalate Yet When

- Java still exposes the needed request values
- replay can reuse the app or hook point
- the user does not need offline execution

## Escalate Further Only When

- offline generation is required
- deeper algorithm recovery is required
- unidbg or SO-level execution is explicitly needed

## Output

- Java entrypoint
- SO name
- JNI style
- input tuple
- output role
- recommended next step
