package com.keydown.privchat_client

import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebView
import androidx.core.view.WindowCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

@Suppress("DEPRECATION")
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // 防截图 / 防最近任务预览：聊天内容不该出现在系统截屏和任务切换里。
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    )
    // Let Android resize the WebView when the IME opens instead of panning
    // the whole activity above the keyboard.
    window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    WindowCompat.setDecorFitsSystemWindows(window, true)
    super.onCreate(savedInstanceState)
    window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (hasFocus) {
      window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // 这段是纯布局微调，任何异常都不该让 App 起不来。
    try {
      installInsetsListener(webView)
    } catch (t: Throwable) {
      android.util.Log.w("privchat", "insets listener skipped", t)
    }
  }

  private fun installInsetsListener(webView: WebView) {
    ViewCompat.setOnApplyWindowInsetsListener(webView) { view, insets ->
      val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
      val imeBottom = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
      val bottomInset = maxOf(imeBottom, systemBars.bottom)
      val rootHeight = view.rootView.height
      if (rootHeight > 0) {
        val availableHeight = (rootHeight - systemBars.top - bottomInset).coerceAtLeast(1)
        val params = view.layoutParams
        if (params.height != availableHeight) {
          params.height = availableHeight
          view.layoutParams = params
        }
        view.translationY = systemBars.top.toFloat()
      }
      insets
    }
    ViewCompat.requestApplyInsets(webView)
  }
}
