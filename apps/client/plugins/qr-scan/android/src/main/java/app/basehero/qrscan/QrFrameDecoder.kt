package app.basehero.qrscan

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.nio.ByteBuffer

/**
 * The luminance (Y) plane of one camera frame, as the camera laid it out:
 * row and pixel strides, and the crop rectangle that holds the image.
 */
class LumaPlane(
    val buffer: ByteBuffer,
    val width: Int,
    val height: Int,
    val rowStride: Int,
    val pixelStride: Int,
    val cropLeft: Int,
    val cropTop: Int,
    val cropWidth: Int,
    val cropHeight: Int,
)

/**
 * Algorithmic QR decoding of one frame's luminance; no model and no network.
 * QR finder patterns fix the code's orientation, so the frame's rotation does
 * not matter. A malformed layout or an unreadable frame gives null.
 */
object QrFrameDecoder {
    private const val MAX_SIDE = 8192
    private val hints = mapOf(DecodeHintType.TRY_HARDER to true)

    fun decode(plane: LumaPlane): String? {
        val pixels = copy(plane) ?: return null
        val source = PlanarYUVLuminanceSource(pixels, plane.cropWidth, plane.cropHeight,
            0, 0, plane.cropWidth, plane.cropHeight, false)
        return try {
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: ReaderException) {
            null // not found, or a failed checksum or format
        } catch (_: RuntimeException) {
            null // a decoder fault on a hostile code is not a scanned code either
        }
    }

    /** The crop's luminance, one byte per pixel, or null for an inconsistent layout. */
    private fun copy(plane: LumaPlane): ByteArray? = with(plane) {
        if (width !in 1..MAX_SIDE || height !in 1..MAX_SIDE || pixelStride < 1 ||
            rowStride.toLong() < (width - 1).toLong() * pixelStride + 1 ||
            cropLeft < 0 || cropTop < 0 || cropWidth !in 1..width || cropHeight !in 1..height ||
            cropLeft > width - cropWidth || cropTop > height - cropHeight) return null
        val base = buffer.position()
        val last = (cropTop + cropHeight - 1).toLong() * rowStride +
            (cropLeft + cropWidth - 1).toLong() * pixelStride
        if (base + last >= buffer.limit()) return null
        val out = ByteArray(cropWidth * cropHeight)
        val rows = buffer.duplicate()
        for (y in 0 until cropHeight) {
            val start = base + (cropTop + y) * rowStride + cropLeft * pixelStride
            if (pixelStride == 1) {
                rows.position(start)
                rows.get(out, y * cropWidth, cropWidth)
            } else {
                for (x in 0 until cropWidth) out[y * cropWidth + x] = buffer.get(start + x * pixelStride)
            }
        }
        out
    }
}
