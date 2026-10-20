package app.basehero.continuityinstrument;

import android.app.Activity;
import android.app.Application;
import android.app.Instrumentation;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** A separate APK attached before WebDriver creates any editable before-state. */
public final class ContinuityInstrumentation extends Instrumentation {
    private static final String TAG = "BhContinuityActivity";
    private final CountDownLatch command = new CountDownLatch(1);
    private final CountDownLatch resumed = new CountDownLatch(1);
    private volatile Activity current;
    private volatile Activity previous;

    private final Application.ActivityLifecycleCallbacks lifecycle = new Application.ActivityLifecycleCallbacks() {
        @Override public void onActivityResumed(Activity activity) {
            if (!"app.basehero.client.MainActivity".equals(activity.getClass().getName())) return;
            current = activity;
            Log.i(TAG, "resumed activity=" + System.identityHashCode(activity));
            if (previous != null && previous != activity) resumed.countDown();
        }
        @Override public void onActivityCreated(Activity a, Bundle state) { }
        @Override public void onActivityStarted(Activity a) { }
        @Override public void onActivityPaused(Activity a) { }
        @Override public void onActivityStopped(Activity a) { }
        @Override public void onActivitySaveInstanceState(Activity a, Bundle state) { }
        @Override public void onActivityDestroyed(Activity a) { }
    };
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "recreate command received");
            command.countDown();
        }
    };

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        Log.i(TAG, "instrumentation onCreate pid=" + Process.myPid());
        start();
    }

    @Override public void onStart() {
        super.onStart();
        Application app = (Application) getTargetContext().getApplicationContext();
        app.registerActivityLifecycleCallbacks(lifecycle);
        getTargetContext().registerReceiver(receiver,
            new IntentFilter("app.basehero.continuitytest.RECREATE"), Context.RECEIVER_EXPORTED);
        try {
            Log.i(TAG, "ready pid=" + Process.myPid());
            // Resume identities alone show whether system settings recreated
            // MainActivity; a recreate command is optional, never awaited as a
            // failure, so a run that sends none never ends the app process.
            if (!command.await(30, TimeUnit.MINUTES)) return;
            previous = current;
            if (previous == null) throw new IllegalStateException("no resumed MainActivity");
            int before = System.identityHashCode(previous), pid = Process.myPid();
            runOnMainSync(previous::recreate);
            if (!resumed.await(30, TimeUnit.SECONDS)) throw new IllegalStateException("no replacement MainActivity");
            if (current == previous || Process.myPid() != pid) throw new IllegalStateException("not same-process recreation");
            Log.i(TAG, "recreated before=" + before + " after=" + System.identityHashCode(current) + " pid=" + pid);
            // Remain attached until the runner force-stops the verified live PID.
            new CountDownLatch(1).await(30, TimeUnit.MINUTES);
        } catch (Exception error) {
            Log.e(TAG, "recreation failed", error);
            finish(-1, new Bundle());
        } finally {
            getTargetContext().unregisterReceiver(receiver);
            app.unregisterActivityLifecycleCallbacks(lifecycle);
        }
    }
}
