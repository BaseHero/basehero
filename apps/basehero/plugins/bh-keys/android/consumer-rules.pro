# Rust calls KeysPlugin through JNI, which R8 can't see.
-keep class app.basehero.keys.KeysPlugin { public *; }
