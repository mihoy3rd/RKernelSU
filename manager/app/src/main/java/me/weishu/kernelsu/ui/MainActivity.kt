package me.weishu.kernelsu.ui

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.compose.rememberNavController
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.utils.isRouteOnBackStackAsState
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.ui.screen.BottomBarDestination
import me.weishu.kernelsu.ui.theme.CardConfig
import me.weishu.kernelsu.ui.theme.KernelSUTheme
import me.weishu.kernelsu.ui.theme.loadCustomBackground
import me.weishu.kernelsu.ui.theme.loadThemeMode
import me.weishu.kernelsu.ui.util.LocalSnackbarHost
import me.weishu.kernelsu.ui.util.rootAvailable
import me.weishu.kernelsu.ui.util.install

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {

        // Enable edge to edge
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        super.onCreate(savedInstanceState)
        
                 // 加载保存的背景设置
         loadCustomBackground()
         loadThemeMode()
         CardConfig.load(applicationContext)

         val isManager = Natives.becomeManager(ksuApp.packageName)
         if (isManager) install()

        setContent {
            KernelSUTheme {
                val navController = rememberNavController()
                val snackBarHostState = remember { SnackbarHostState() }
                Scaffold(
                    bottomBar = { BottomBar(navController) },
                    contentWindowInsets = WindowInsets(0, 0, 0, 0)
                ) { innerPadding ->
                    CompositionLocalProvider(
                        LocalSnackbarHost provides snackBarHostState,
                    ) {
                        DestinationsNavHost(
                            modifier = Modifier.padding(innerPadding),
                            navGraph = NavGraphs.root,
                            navController = navController,
                            defaultTransitions = object : NavHostAnimatedDestinationStyle() {
                                override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition
                                    get() = { fadeIn(animationSpec = tween(340)) }
                                override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition
                                    get() = { fadeOut(animationSpec = tween(340)) }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BottomBar(navController: NavHostController) {
    val navigator = navController.rememberDestinationsNavigator()
    val isManager = Natives.becomeManager(ksuApp.packageName)
    val fullFeatured = isManager && !Natives.requireNewKernel() && rootAvailable()
    
    // 获取卡片颜色和透明度
    val cardColor = MaterialTheme.colorScheme.secondaryContainer
    val cardAlpha = CardConfig.cardAlpha
    val cardElevation = CardConfig.cardElevation

     NavigationBar(
        tonalElevation = cardElevation, // 动态设置阴影
        containerColor = cardColor.copy(alpha = cardAlpha), // 动态设置颜色和透明度
        contentColor = if (cardColor.luminance() > 0.5) Color.Black else Color.White, // 根据背景亮度设置文字颜色
        windowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout).only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom
        )
    ) {
        BottomBarDestination.entries.forEach { destination ->
            if (!fullFeatured && destination.rootRequired) return@forEach
            val isCurrentDestOnBackStack by navController.isRouteOnBackStackAsState(destination.direction)
            NavigationBarItem(
                selected = isCurrentDestOnBackStack,
                onClick = {
                    if (isCurrentDestOnBackStack) {
                        navigator.popBackStack(destination.direction, false)
                    }
                    navigator.navigate(destination.direction) {
                        popUpTo(NavGraphs.root) {
                            saveState = true
                        }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                icon = {
                    if (isCurrentDestOnBackStack) {
                        Icon(destination.iconSelected, stringResource(destination.label))
                    } else {
                        Icon(destination.iconNotSelected, stringResource(destination.label))
                    }
                },
                label = { Text(stringResource(destination.label)) },
                alwaysShowLabel = false
            )
        }
    }
}
