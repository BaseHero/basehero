package app.basehero.continuityime;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.inputmethodservice.InputMethodService;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.EditorInfo;

/** Disposable emulator-only IME. Composes through Android's InputConnection, never DOM events. */
public final class ContinuityIme extends InputMethodService {
    private static final String TAG = "BhContinuityIme";
    private static final String PREFIX = "app.basehero.continuityime.";
    private final BroadcastReceiver commands = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            InputConnection connection = getCurrentInputConnection();
            if (connection == null) {
                Log.e(TAG, "no active InputConnection for " + intent.getAction());
                return;
            }
            if ((PREFIX + "COMPOSE").equals(intent.getAction())) {
                String text = intent.getStringExtra("text");
                if (text == null || text.length() != 1) { Log.e(TAG, "invalid composing text"); return; }
                Log.i(TAG, "compose=" + connection.setComposingText(text, 1));
            } else if ((PREFIX + "FINISH").equals(intent.getAction())) {
                Log.i(TAG, "finish=" + connection.finishComposingText());
            }
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        IntentFilter filter = new IntentFilter();
        filter.addAction(PREFIX + "COMPOSE");
        filter.addAction(PREFIX + "FINISH");
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(commands, filter, Context.RECEIVER_EXPORTED);
        else registerReceiver(commands, filter);
        Log.i(TAG, "ready");
    }

    @Override public void onStartInput(EditorInfo info, boolean restarting) {
        super.onStartInput(info, restarting);
        Log.i(TAG, "input-ready connected=" + (getCurrentInputConnection() != null));
    }

    @Override public boolean onEvaluateFullscreenMode() { return false; }

    @Override public View onCreateInputView() {
        // A bare View measures to the entire offered height. Give this
        // keyboard a real height, leaving the editor visible in both postures.
        View keyboard = new View(this) {
            @Override protected void onMeasure(int widthSpec, int heightSpec) {
                setMeasuredDimension(MeasureSpec.getSize(widthSpec), 240);
            }
        };
        keyboard.setBackgroundColor(Color.rgb(230, 230, 240));
        return keyboard;
    }

    @Override public void onDestroy() {
        unregisterReceiver(commands);
        super.onDestroy();
    }
}
