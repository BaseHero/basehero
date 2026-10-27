# Connect on Android

## Android contract

Use the versioned activity request and result to connect an app.

## Caller manifest and plugin

Declare visibility of BaseHero and verify the receiving app before requesting access.

## Keep credentials in native code

Pass the connection result from Kotlin to Rust without involving a WebView.

## What the person sees

Show the requested bases and explain reconnection to the person approving access.

## Errors

Handle cancellation, invalid requests, and required updates in the caller.

## Test with a development build

Try the flow with a development build before shipping your app.
