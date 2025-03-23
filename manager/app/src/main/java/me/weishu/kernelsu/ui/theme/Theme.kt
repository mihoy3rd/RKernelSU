package me.weishu.kernelsu.ui.theme

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.paint
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.zIndex
import coil.compose.rememberAsyncImagePainter
import androidx.compose.foundation.background
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

private val DarkColorScheme = darkColorScheme(
    primary = YELLOW,
    secondary = YELLOW_DARK,
    tertiary = SECONDARY_DARK,
    background = Color.Transparent,
    surface = Color.Transparent
)

private val LightColorScheme = lightColorScheme(
    primary = YELLOW,
    secondary = YELLOW_LIGHT,
    tertiary = SECONDARY_LIGHT,
    background = Color.Transparent,
    surface = Color.Transparent
)

object ThemeConfig {
    var customBackgroundUri by mutableStateOf<Uri?>(null)
    var forceDarkMode by mutableStateOf<Boolean?>(null) // null表示跟随系统
}

// 复制图片到应用内部存储
fun Context.copyImageToInternalStorage(uri: Uri): Uri? {
    try {
        val contentResolver: ContentResolver = contentResolver
        val inputStream: InputStream = contentResolver.openInputStream(uri)!!
        val fileName = "custom_background.jpg"
        val file = File(filesDir, fileName)
        val outputStream = FileOutputStream(file)
        val buffer = ByteArray(4 * 1024)
        var read: Int
        while (inputStream.read(buffer).also { read = it } != -1) {
            outputStream.write(buffer, 0, read)
        }
        outputStream.flush()
        outputStream.close()
        inputStream.close()
        return Uri.fromFile(file)
    } catch (e: Exception) {
        Log.e("ImageCopy", "Failed to copy image: ${e.message}")
        return null
    }
}

@Composable
fun KernelSUTheme(
    darkTheme: Boolean = when(ThemeConfig.forceDarkMode) {
        true -> true
        false -> false
        null -> isSystemInDarkTheme()
    },
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    // 在应用启动时加载自定义背景设置
    context.loadCustomBackground()
    
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context).copy(
                background = Color.Transparent,
                surface = Color.Transparent
            ) else dynamicLightColorScheme(context).copy(
                background = Color.Transparent,
                surface = Color.Transparent
            )
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
typography = Typography
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            // 背景图层
            ThemeConfig.customBackgroundUri?.let { uri ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .zIndex(-1f)
                ) {
                    // 背景图片
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .paint(
                                painter = rememberAsyncImagePainter(
                                    model = uri,
                                    onError = {
                                        // 图片加载失败，清空 Uri 并保存
                                        ThemeConfig.customBackgroundUri = null
                                        context.saveCustomBackground(null)
                                    }
                                ),
                                contentScale = ContentScale.Crop
                            )
                    )

                    // 亮度调节层
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                if (darkTheme) {
                                    Color.Black.copy(alpha = 0.4f)
                                } else {
                                    Color.White.copy(alpha = 0.1f)
                                }
                            )
                    )

                    // 边缘渐变遮罩层
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(
                                        Color.Transparent,
                                        if (darkTheme) {
                                            Color.Black.copy(alpha = 0.5f)
                                        } else {
                                            Color.Black.copy(alpha = 0.2f)
                                        }
                                    ),
                                    radius = 1200f
                                )
                            )
                    )
                }
            }
            // 内容图层
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .zIndex(1f)
            ) {
                content()
            }
        }
    }
}

// 用于保存和加载背景图片 URI 的扩展函数
 fun Context.saveCustomBackground(uri: Uri?) {
    val newUri = uri?.let { copyImageToInternalStorage(it) }
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit()
        .putString("custom_background", newUri?.toString())
        .apply()
    ThemeConfig.customBackgroundUri = newUri
}
fun Context.loadCustomBackground() {
    val uriString = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getString("custom_background", null)
    ThemeConfig.customBackgroundUri = uriString?.let { Uri.parse(it) }
}
fun Context.saveThemeMode(forceDark: Boolean?) {
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit()
        .putString("theme_mode", when(forceDark) {
            true -> "dark"
            false -> "light"
            null -> "system"
        })
        .apply()
    ThemeConfig.forceDarkMode = forceDark
}

fun Context.loadThemeMode() {
    val mode = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getString("theme_mode", "system")
    ThemeConfig.forceDarkMode = when(mode) {
        "dark" -> true
        "light" -> false
        else -> null
    }
}
