package me.weishu.kernelsu.ui.util

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.R
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ModuleModify {
    suspend fun showRestoreConfirmation(context: Context): Boolean {
        val result = CompletableDeferred<Boolean>()
        withContext(Dispatchers.Main) {
            AlertDialog.Builder(context)
                .setTitle(context.getString(R.string.restore_confirm_title))
                .setMessage(context.getString(R.string.restore_confirm_message))
                .setPositiveButton(context.getString(R.string.confirm)) { _, _ -> result.complete(true) }
                .setNegativeButton(context.getString(R.string.cancel)) { _, _ -> result.complete(false) }
                .setOnCancelListener { result.complete(false) }
                .show()
        }
        return result.await()
    }

    suspend fun backupModules(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        withContext(Dispatchers.IO) {
            try {
                val busyboxPath = "/data/adb/ksu/bin/busybox"
                val moduleDir = "/data/adb/modules"
                val tempFile = File(context.cacheDir, "backup_${System.currentTimeMillis()}.tar.gz")
                val tempPath = tempFile.absolutePath

                val command = """
                    cd "$moduleDir" &&
                    $busyboxPath tar -czvf "$tempPath" ./*
                """.trimIndent()

                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                context.contentResolver.openOutputStream(uri)?.use { output ->
                    tempFile.inputStream().use { input ->
                        input.copyTo(output)
                    }
                }

                tempFile.delete()

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.backup_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("Backup", context.getString(R.string.backup_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.backup_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun restoreModules(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        val userConfirmed = showRestoreConfirmation(context)
        if (!userConfirmed) return

        withContext(Dispatchers.IO) {
            try {
                val busyboxPath = "/data/adb/ksu/bin/busybox"
                val moduleDir = "/data/adb/modules"
                val tempFile = File(context.cacheDir, "temp_restore.tar.gz").apply {
                    if (exists()) delete()
                }

                context.contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }

                val command = """
                    cd "$moduleDir" &&
                    rm -rf * && 
                    $busyboxPath tar -xzvf "${tempFile.absolutePath}"
                """.trimIndent()

                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                tempFile.delete()

                withContext(Dispatchers.Main) {
                    val snackbarResult = snackBarHost.showSnackbar(
                        message = context.getString(R.string.restore_success),
                        actionLabel = context.getString(R.string.restart_now),
                        duration = SnackbarDuration.Long
                    )
                    if (snackbarResult == SnackbarResult.ActionPerformed) {
                        reboot()
                    }
                }

            } catch (e: Exception) {
                Log.e("Restore", context.getString(R.string.restore_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        message = context.getString(
                            R.string.restore_failed,
                            e.message ?: context.getString(R.string.unknown_error)
                        ),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun showAllowlistRestoreConfirmation(context: Context): Boolean {
        val result = CompletableDeferred<Boolean>()
        withContext(Dispatchers.Main) {
            AlertDialog.Builder(context)
                .setTitle(context.getString(R.string.allowlist_restore_confirm_title))
                .setMessage(context.getString(R.string.allowlist_restore_confirm_message))
                .setPositiveButton(context.getString(R.string.confirm)) { _, _ -> result.complete(true) }
                .setNegativeButton(context.getString(R.string.cancel)) { _, _ -> result.complete(false) }
                .setOnCancelListener { result.complete(false) }
                .show()
        }
        return result.await()
    }

    suspend fun backupAllowlist(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        withContext(Dispatchers.IO) {
            try {
                val allowlistPath = "/data/adb/ksu/.allowlist"
                val tempFile = File(context.cacheDir, "allowlist_backup_${System.currentTimeMillis()}")

                val command = "cp $allowlistPath ${tempFile.absolutePath}"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                context.contentResolver.openOutputStream(uri)?.use { output ->
                    tempFile.inputStream().use { input ->
                        input.copyTo(output)
                    }
                }

                tempFile.delete()

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("AllowlistBackup", context.getString(R.string.allowlist_backup_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun restoreAllowlist(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        val userConfirmed = showAllowlistRestoreConfirmation(context)
        if (!userConfirmed) return

        withContext(Dispatchers.IO) {
            try {
                val allowlistPath = "/data/adb/ksu/.allowlist"
                val tempFile = File(context.cacheDir, "allowlist_restore_temp").apply {
                    if (exists()) delete()
                }

                context.contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }

                val command = "cp ${tempFile.absolutePath} $allowlistPath"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                tempFile.delete()

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("AllowlistRestore", context.getString(R.string.allowlist_restore_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    @Composable
    fun rememberModuleBackupLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    backupModules(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberModuleRestoreLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    restoreModules(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistBackupLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    backupAllowlist(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistRestoreLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    restoreAllowlist(context, snackBarHost, uri)
                }
            }
        }
    }

    fun createBackupIntent(): Intent {
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/zip"
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            putExtra(Intent.EXTRA_TITLE, "modules_backup_$timestamp.zip")
        }
    }

    fun createRestoreIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/zip"
        }
    }

    fun createAllowlistBackupIntent(): Intent {
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            putExtra(Intent.EXTRA_TITLE, "ksu_allowlist_backup_$timestamp.dat")
        }
    }

    fun createAllowlistRestoreIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
    }
}
