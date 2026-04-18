# Android Static Triage And Call Flow

Use this file first for Android request, sign, and crypto tasks after runtime-first Android pentest work has shown that network-layer testing alone is not enough.
It is not the default entrypoint for a general authorized Android app pentest.

## Owns

- manifest and entry-component reading
- package and architecture survey
- network stack identification
- call-flow tracing from UI or component to request execution
- sign-path and encrypt-path location in Java

## Static Order

1. read `AndroidManifest.xml`
2. identify application class and entry components
3. find package areas around `api`, `network`, `data`, `repository`, `service`, `retrofit`, `http`
4. identify the network framework
5. trace the request chain down to builder, interceptor, signer, encryptor, or serializer

## Common Call Flow

```text
Activity / Fragment / Service
-> ViewModel / Presenter / UseCase
-> Repository / DataSource
-> ApiService / RequestBuilder / Interceptor
-> Signer / Encryptor / Serializer
```

## Strong Anchors

- Retrofit annotations
- `Request.Builder`, `HttpUrl`, interceptor classes
- hardcoded URLs, headers, and token names
- `sign`, `token`, `encrypt`, `decrypt`, `cipher`, `sha`, `hmac`, `md5`
- `native`, `System.loadLibrary`, `System.load`

## Completion Standard

Stop static triage when you can state:

- the network stack
- the request method and path
- where headers and body are written
- where sign inputs converge
- whether the path is Java-only, mixed Java/JNI, or mostly native
