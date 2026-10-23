package app.basehero.notify

import android.Manifest
import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import app.tauri.PermissionState
import app.tauri.annotation.Command
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

/** Rust-only: neither a JS permission nor a page callback can post an alert. */
@TauriPlugin(permissions = [Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "notifications")])
class NotifyPlugin(private val activity: Activity) : Plugin(activity) {
    private var waiting: Pair<String, String>? = null
    @Command
    fun notify(invoke: Invoke) {
        val args = invoke.getArgs()
        val body = args.optString("body", "")
        val tag = args.optString("tag", "")
        if (body.isBlank() || tag.isBlank()) { invoke.reject("invalid notification"); return }
        activity.runOnUiThread {
            if (Build.VERSION.SDK_INT >= 33 && getPermissionState("notifications") != PermissionState.GRANTED) {
                waiting = Pair(tag, body)
                requestPermissionForAlias("notifications", invoke, "notificationPermissionResult")
                return@runOnUiThread
            }
            post(tag, body)
            invoke.resolve()
        }
    }
    @PermissionCallback
    fun notificationPermissionResult(invoke: Invoke) {
        val alert = waiting
        waiting = null
        if (alert != null && getPermissionState("notifications") == PermissionState.GRANTED) post(alert.first, alert.second)
        invoke.resolve()
    }
    private fun post(tag: String, body: String) {
            val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = "basehero-security"
            if (Build.VERSION.SDK_INT >= 26) manager.createNotificationChannel(
                NotificationChannel(channel, "Security alerts", NotificationManager.IMPORTANCE_DEFAULT))
            @Suppress("DEPRECATION")
            val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(activity, channel) else Notification.Builder(activity)
            builder.setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Security alert")
                .setContentText(body)
                .setAutoCancel(true)
            manager.notify(tag, 0, builder.build())
    }
}
