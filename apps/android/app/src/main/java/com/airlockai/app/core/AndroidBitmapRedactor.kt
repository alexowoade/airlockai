package com.airlockai.app.core

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF

data class PixelRedactionBox(
    val left: Float,
    val top: Float,
    val right: Float,
    val bottom: Float,
    val label: String,
)

/**
 * On-device Android Canvas pixel redactor: burns opaque black rectangles and placeholder labels
 * directly into local bitmap pixel buffers before any preview, export, or sharing (0B sent).
 */
object AndroidBitmapRedactor {

    fun clampRedactionBoxes(
        boxes: List<PixelRedactionBox>,
        width: Int,
        height: Int,
    ): List<PixelRedactionBox> {
        val maxW = width.coerceAtLeast(1).toFloat()
        val maxH = height.coerceAtLeast(1).toFloat()
        return boxes.mapNotNull { b ->
            val l = b.left.coerceIn(0f, maxW)
            val t = b.top.coerceIn(0f, maxH)
            val r = b.right.coerceIn(0f, maxW)
            val bt = b.bottom.coerceIn(0f, maxH)
            if (r - l >= 2f && bt - t >= 2f) {
                PixelRedactionBox(l, t, r, bt, b.label)
            } else {
                null
            }
        }
    }

    fun redactBitmapPixels(source: Bitmap, boxes: List<PixelRedactionBox>): Bitmap {
        val safeCopy = source.copy(Bitmap.Config.ARGB_8888, true)
        val canvas = Canvas(safeCopy)
        val clamped = clampRedactionBoxes(boxes, safeCopy.width, safeCopy.height)

        val fillPaint = Paint().apply {
            color = Color.BLACK
            style = Paint.Style.FILL
            isAntiAlias = false
        }
        val textPaint = Paint().apply {
            color = Color.WHITE
            textSize = 20f
            isAntiAlias = true
        }

        for (box in clamped) {
            val rect = RectF(box.left, box.top, box.right, box.bottom)
            canvas.drawRect(rect, fillPaint)
            if (box.label.isNotBlank() && (box.bottom - box.top) >= 18f) {
                canvas.drawText(box.label, box.left + 4f, box.bottom - 4f, textPaint)
            }
        }
        return safeCopy
    }
}
